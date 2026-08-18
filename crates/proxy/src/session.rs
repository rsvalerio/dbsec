//! One client connection: startup negotiation (including TLS on either hop),
//! then a frame-aware relay in each direction. The upstream→client relay runs
//! the row decryptor; the client→upstream relay runs the query rewriter.
//!
//! The two directions share one [`SessionPortals`]: the extended protocol
//! splits a single conversation across both of them, and the decryptor cannot
//! tell which statement a DataRow belongs to without what the rewriter saw.
//!
//! Each relay can also answer the sender directly instead of forwarding a
//! frame ([`FrameAction::Reply`]) — that is how the write path refuses a
//! statement with an ErrorResponse without dropping the connection. Both
//! writers are therefore shared: a relay writes its own direction and, on a
//! refusal, the other one. Whole frames are written under the lock, so the
//! two directions never interleave inside a message.
//!
//! Authentication is *relayed*, never terminated: the SASL frames go across
//! verbatim, so the proxy holds no credential and needs no auth implementation
//! of its own. Two consequences are structural rather than oversights, and are
//! written down in `README.md` and `plans/PLAN.md` for operators:
//!
//! - `SCRAM-SHA-256-PLUS` cannot work. Channel binding ties the client's proof
//!   to its own TLS session's endpoint data, and there are two independent TLS
//!   sessions here, so the proof the client computes over the downstream
//!   channel is checked by the server against the upstream one. A client that
//!   selects `-PLUS` fails to authenticate, and `channel_binding=require`
//!   cannot connect at all. Supporting it means re-originating SCRAM, which
//!   means holding the client's credential — rejected; per-hop `verify-full`
//!   TLS is what stands in for it.
//! - `GSSENCRequest` is always answered `N` ([`start_session`]), because
//!   nothing here speaks GSSAPI. The client falls back to the ordinary startup
//!   flow, which is plaintext unless downstream TLS is configured.
//!
//! The read path refuses in the other direction, and does not stop there
//! ([`FrameAction::RefuseAndClose`]): the client is the *receiver*, so the
//! ErrorResponse replacing a result set the decryptor will not relay travels
//! forward — and then the session ends, because a refused read's statement has
//! already run and only closing the connection stops the rest of its batch.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use dbsec_core::pgwire::{self, Startup};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{watch, Mutex};
use tokio::time::timeout;

use crate::encrypt::{QueryRewriter, StartupSettings, WriteCatalog};
use crate::portal::SessionPortals;
use crate::rows::RowContext;
use crate::tls::{MaybeTls, TlsContext};
use crate::{Error, CONNECT_TIMEOUT};

/// Deadline for the downstream TLS handshake on its own. It sits inside the
/// session's overall startup deadline so a peer that opens a connection and
/// then stalls the handshake cannot pin the task even when the startup budget
/// is generous.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Relay buffer capacity kept between frames. A larger buffer is released
/// once its frame has been relayed, so a single 1 GiB frame does not reserve
/// 1 GiB for the life of the session (SEC-33).
const RELAY_BUFFER_RETAIN: usize = 64 * 1024;

/// How long the surviving relay direction may keep running after the other
/// one has finished — see [`join_relays`].
const RELAY_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Receiver of the process-wide "stop taking new work" signal. Sessions
/// observe it at frame boundaries only — see [`relay`]. A *dropped* sender
/// counts as shutdown too: the only thing holding it is `main::serve`, so its
/// disappearance means the accept loop is gone.
pub type ShutdownRx = watch::Receiver<bool>;

/// The backend's transaction status before any ReadyForQuery has been seen.
const TX_IDLE: u8 = b'I';

/// One relay direction: the label its log lines carry, and the bound it puts
/// on an inbound frame body *before* that body is buffered.
///
/// The two travel together because both are properties of the side being read
/// from, and because keeping them apart would put a sixth parameter on
/// [`relay`] (FN-3).
struct Direction {
    name: &'static str,
    limit: BodyLimit,
}

impl Direction {
    /// A direction bounded only by the protocol's own limit. That is what
    /// upstream→client always is: the backend is the peer this proxy was
    /// configured to talk to, not the anonymous one the pre-authentication
    /// bound exists to hold back.
    fn unbounded(name: &'static str) -> Self {
        Self { name, limit: BodyLimit::Full }
    }
}

/// How large an inbound frame body one direction may be, re-asked per frame.
enum BodyLimit {
    /// [`pgwire::MAX_MESSAGE_LEN`], always.
    Full,
    /// [`pgwire::MAX_PRE_AUTH_MESSAGE_LEN`] until the flag is set, then
    /// [`pgwire::MAX_MESSAGE_LEN`] — see [`note_authentication`].
    UntilAuthenticated(Arc<AtomicBool>),
}

impl BodyLimit {
    /// `Relaxed` is the whole ordering requirement: the flag publishes no other
    /// data, and it is set by the transform of the very AuthenticationOk whose
    /// forwarding is what lets the client send the frame this bound is being
    /// asked about — so the two are already ordered by the protocol, not by
    /// this load.
    fn max_body(&self) -> usize {
        match self {
            Self::Full => pgwire::MAX_MESSAGE_LEN,
            Self::UntilAuthenticated(seen) if seen.load(Ordering::Relaxed) => {
                pgwire::MAX_MESSAGE_LEN
            }
            Self::UntilAuthenticated(_) => pgwire::MAX_PRE_AUTH_MESSAGE_LEN,
        }
    }
}

/// Everything a session needs beyond its socket.
pub struct SessionContext {
    pub upstream_addr: String,
    /// Shared with the column refresher, which needs the same trust roots for
    /// its control connection.
    pub tls: Arc<TlsContext>,
    pub rows: Option<Arc<RowContext>>,
    pub writes: Option<Arc<WriteCatalog>>,
    /// Deadline for the whole client-controlled startup phase.
    pub startup_timeout: Duration,
}

/// What the relay does with one frame.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameAction {
    /// Forward it unchanged.
    Relay,
    /// Forward this body in place of the original.
    Replace(Vec<u8>),
    /// Do not forward it; write these already-framed bytes back to the sender
    /// instead. Empty means the frame is dropped without an answer, which is
    /// what the backend does to the rest of a batch it has errored on.
    Reply(Vec<u8>),
    /// Do not forward it; write these already-framed bytes on to the receiver
    /// in its place, then end the session in both directions.
    ///
    /// [`Replace`](Self::Replace) cannot express this: it keeps the original
    /// message type, and a refusal has to change one (a DataRow becomes an
    /// ErrorResponse). It is the read path's counterpart to
    /// [`Reply`](Self::Reply) — there the client is the *receiver*, so the
    /// frames that tell it why its statement was refused travel forward rather
    /// than back.
    ///
    /// Closing is the other half, and is what makes this different from its
    /// write-path sibling rather than a mirror of it. A refused write is
    /// withheld before it reaches the backend, so the backend never runs it and
    /// answering the client is the whole story. A refused read is the opposite:
    /// the statement has already run upstream, and the frames being refused are
    /// its *results*. Answering the client without stopping the backend leaves
    /// the rest of an implicit-transaction batch — `SELECT protected;
    /// UPDATE …` — to execute and commit behind an error the client was told
    /// means nothing happened.
    ///
    /// There is no in-band way to abort a batch the backend is already
    /// executing; closing the connection is what makes it roll back. So the
    /// client is told *why* (the ErrorResponse it would otherwise never see)
    /// and the connection ends — strictly more than the bare socket drop this
    /// path used to do, and strictly safer than resynchronising.
    RefuseAndClose(Vec<u8>),
}

/// What the startup phase hands the relay.
struct Started {
    client: MaybeTls<TcpStream>,
    upstream: MaybeTls<TcpStream>,
    /// What the startup packet already moved: the session settings the rewrite
    /// depends on, in whatever state the connection begins in.
    settings: StartupSettings,
}

pub async fn run(
    client: TcpStream,
    ctx: &SessionContext,
    shutdown: ShutdownRx,
) -> Result<(), Error> {
    // Everything up to the forwarded startup message is driven by the client,
    // so it gets one deadline: without it a peer that connects and sends
    // nothing (or dribbles a 1 GiB startup message a byte at a time) holds a
    // task and two descriptors forever (SEC-33).
    let started = timeout(ctx.startup_timeout, start_session(client, ctx))
        .await
        .map_err(|_| Error::StartupTimeout { timeout: ctx.startup_timeout })??;
    let Some(Started { client, upstream, settings }) = started else {
        return Ok(()); // client connected and left (health check)
    };

    // Both halves are configured together (`main::serve` builds them from the
    // same `[[column]]` list), so the decryptor is never left reading a
    // conversation nobody is tracking.
    let portals = SessionPortals::new();
    let mut decryptor = ctx.rows.as_ref().map(|rows| rows.decryptor(portals.clone()));
    let copy_state = portals.clone();
    let tx_status = Arc::new(AtomicU8::new(TX_IDLE));
    let seen_status = tx_status.clone();
    let mut rewriter = ctx.writes.as_ref().map(|writes| {
        QueryRewriter::new(writes.clone(), portals, ctx.rows.clone(), tx_status, settings)
    });
    // The startup packet is forwarded by now, so `MAX_STARTUP_MESSAGE_LEN` is
    // behind us — but the client is still anonymous until the backend says
    // otherwise, and this is what says so (SEC-33).
    let authenticated = Arc::new(AtomicBool::new(false));
    let seen_authentication = authenticated.clone();
    let (client_r, client_w) = tokio::io::split(client);
    let (upstream_r, upstream_w) = tokio::io::split(upstream);
    let client_w = Arc::new(Mutex::new(client_w));
    let upstream_w = Arc::new(Mutex::new(upstream_w));
    join_relays(
        relay(
            client_r,
            Writers { forward: upstream_w.clone(), back: client_w.clone() },
            Direction {
                name: "client->upstream",
                limit: BodyLimit::UntilAuthenticated(authenticated),
            },
            move |msg_type, body| match &mut rewriter {
                Some(rewriter) => rewriter.on_frame(msg_type, body),
                None => Ok(FrameAction::Relay),
            },
            shutdown.clone(),
        ),
        relay(
            upstream_r,
            Writers { forward: client_w, back: upstream_w },
            Direction::unbounded("upstream->client"),
            move |msg_type, body| {
                note_authentication(msg_type, body, &seen_authentication);
                note_backend_state(msg_type, body, &seen_status, &copy_state);
                match &mut decryptor {
                    Some(decryptor) => decryptor.on_frame(msg_type, body),
                    None => Ok(FrameAction::Relay),
                }
            },
            shutdown,
        ),
    )
    .await
}

/// Records the one upstream→client frame that says the client is no longer
/// anonymous, which is what lifts the pre-authentication frame bound
/// ([`BodyLimit::UntilAuthenticated`]).
///
/// The proxy relays authentication rather than terminating it (see the module
/// docs), so the backend's verdict is just another frame going past: `'R'`
/// carries an `i32` request code, and `0` — `AuthenticationOk` — is the only
/// value that means "accepted". The rest of the codes (3 cleartext password,
/// 5 MD5, 10 SASL, 11/12 SASL continue and final) are the exchange still in
/// progress, and a rejection arrives as an ErrorResponse that never reaches
/// here. A short body cannot be an authentication request at all, so it leaves
/// the bound where it is.
///
/// Set *before* the frame is forwarded, which is what makes the flag ordered
/// against the client's next frame without any synchronisation of its own: the
/// client cannot have sent a post-authentication frame before receiving the
/// AuthenticationOk this call is inspecting.
fn note_authentication(msg_type: u8, body: &[u8], authenticated: &AtomicBool) {
    if msg_type == b'R' && body.get(..4) == Some(&0i32.to_be_bytes()[..]) {
        authenticated.store(true, Ordering::Relaxed);
    }
}

/// Records the upstream→client frames whose meaning the *write* path depends
/// on, before the decryptor sees them.
///
/// Neither is row data, which is why it is here rather than in
/// [`crate::rows::RowDecryptor`]:
///
/// - ReadyForQuery carries the backend's transaction status, which is the
///   status byte the rewriter puts on a ReadyForQuery it has to synthesize for
///   a statement it refused.
/// - CopyInResponse (and CopyBothResponse, its replication sibling) is the
///   only evidence that the client's following `CopyData`/`CopyDone`/
///   `CopyFail` frames are the payload of a copy in progress rather than
///   strays the backend silently discards — the write path cannot tell them
///   apart on its own, and acting on a stray lets a client desync the pending
///   queue ([`SessionPortals::copy_data`]).
///
/// Recorded even when no decryptor is configured, since a rewriter still can
/// be.
fn note_backend_state(msg_type: u8, body: &[u8], tx_status: &AtomicU8, portals: &SessionPortals) {
    match msg_type {
        b'Z' => {
            if let Some(&status) = body.first() {
                tx_status.store(status, Ordering::Relaxed);
            }
        }
        b'G' | b'W' => portals.copy_in_started(),
        _ => {}
    }
}

/// Runs both relay directions and ends the session once the first of them
/// does, giving the other only a bounded grace period to finish.
///
/// `try_join!` cannot express this: it waits for *both* halves unless one
/// fails, and a half that is parked in `read_exact` on a peer which never
/// writes again never finishes. Every way a session ends normally goes through
/// that state — an upstream EOF, a read-path
/// [`FrameAction::RefuseAndClose`], a shutdown at a frame boundary — and each
/// of them leaves the opposite direction blocked on a client that is under no
/// obligation to close its own write half. The session, its two descriptors
/// and whatever frame is buffered then linger until the client closes or TCP
/// gives up, which is a resource leak an unauthenticated peer can ask for on
/// purpose (SEC-33).
///
/// The grace period rather than an immediate cancel is deliberate: a
/// half-closing client (`shutdown(SHUT_WR)` and then read to the end) is
/// legitimate, and the results still in flight for its last statement are
/// exactly what the surviving direction is carrying. Ending the moment the
/// first direction does would truncate them. Once one side is gone the other
/// has no more work coming, so bounding it costs nothing a correct peer
/// notices.
///
/// The failure of either direction is what the session reports; if the first
/// one to end failed, the second's outcome cannot change that.
async fn join_relays(
    to_upstream: impl Future<Output = Result<(), Error>>,
    to_client: impl Future<Output = Result<(), Error>>,
) -> Result<(), Error> {
    let mut to_upstream = std::pin::pin!(to_upstream);
    let mut to_client = std::pin::pin!(to_client);
    // Hand-polled rather than `select!` so the *other* future stays reachable
    // afterwards: a `select!` arm cannot await the branch it did not take
    // while the macro still holds it borrowed.
    let (ended, upstream_ended) = std::future::poll_fn(|cx| {
        if let Poll::Ready(result) = to_upstream.as_mut().poll(cx) {
            return Poll::Ready((result, true));
        }
        if let Poll::Ready(result) = to_client.as_mut().poll(cx) {
            return Poll::Ready((result, false));
        }
        Poll::Pending
    })
    .await;

    let draining = async {
        if upstream_ended {
            to_client.as_mut().await
        } else {
            to_upstream.as_mut().await
        }
    };
    match timeout(RELAY_DRAIN_TIMEOUT, draining).await {
        Ok(rest) => ended.and(rest),
        Err(_) => {
            tracing::debug!(
                direction = if upstream_ended { "upstream->client" } else { "client->upstream" },
                "peer did not close its half within the drain deadline; ending the session"
            );
            ended
        }
    }
}

/// Startup phase, run under the caller's deadline: answer SSLRequest and
/// GSSENCRequest locally, upgrade to TLS when configured, connect upstream,
/// and forward the real startup message. Returns both halves of the relay, or
/// `None` when the client hung up before sending anything.
async fn start_session(client: TcpStream, ctx: &SessionContext) -> Result<Option<Started>, Error> {
    let (upstream_addr, tls) = (ctx.upstream_addr.as_str(), &ctx.tls);
    let mut client = MaybeTls::Plain(client);

    let startup = loop {
        let Some(msg) = read_startup_message(&mut client).await? else {
            return Ok(None);
        };
        let mut code = [0u8; 4];
        code.copy_from_slice(&msg[4..8]);
        match pgwire::startup_kind(i32::from_be_bytes(code)) {
            Startup::Tls => match (&tls.acceptor, client) {
                (Some(acceptor), MaybeTls::Plain(mut sock)) => {
                    sock.write_all(b"S").await?;
                    let stream =
                        timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(sock)).await.map_err(
                            |_| Error::TlsHandshakeTimeout { timeout: TLS_HANDSHAKE_TIMEOUT },
                        )??;
                    client = MaybeTls::Server(Box::new(stream));
                }
                // Second SSLRequest, or SSLRequest without TLS configured.
                (_, mut other) => {
                    other.write_all(b"N").await?;
                    client = other;
                }
            },
            // No GSSAPI here, so the client falls back to the ordinary startup
            // flow — over TLS if it asked for that too, in plaintext otherwise.
            // See the module docs: this is a documented limitation, not a
            // negotiation failure.
            Startup::GssEnc => client.write_all(b"N").await?,
            Startup::Cancel | Startup::Protocol(_) => {
                if tls.acceptor.is_some() && client.is_plain() {
                    return Err(Error::PlaintextRejected);
                }
                break msg;
            }
        }
    };

    let upstream_tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(upstream_addr))
        .await
        .map_err(|_| Error::ConnectTimeout { addr: upstream_addr.to_owned() })??;
    let mut upstream = match &tls.connector {
        Some((connector, name)) => {
            let sock = request_upstream_tls(upstream_tcp, upstream_addr).await?;
            MaybeTls::Client(Box::new(connector.connect(name.clone(), sock).await?))
        }
        None => MaybeTls::Plain(upstream_tcp),
    };
    upstream.write_all(&startup).await?;
    Ok(Some(Started { client, upstream, settings: startup_settings(&startup) }))
}

/// The session settings the startup packet already moved, before the first
/// statement is seen.
///
/// Both of them can be set here as well as mid-session, and a client that does
/// it here is in exactly the state a `SET` would have left it in — so the
/// connect-time half is read out of the packet and handed to the rewriter,
/// which tracks the in-session half itself. A driver can spell either one as a
/// startup parameter or inside `options=-c <name>=<value>`:
///
/// - `search_path` off `public` means unqualified names no longer resolve to
///   the schema the write catalog assumes, so bare names stop being resolved;
/// - `standard_conforming_strings` off means PostgreSQL reads a backslash in an
///   ordinary `'…'` literal as the start of an escape while the proxy's parser
///   does not, so the two no longer agree on what such a literal contains.
///
/// Setting names are matched case-insensitively because that is how the server
/// resolves them: `SEARCH_PATH` in a startup packet moves `search_path`.
fn startup_settings(startup: &[u8]) -> StartupSettings {
    let mut settings = StartupSettings::default();
    let Some(mut params) = startup.get(pgwire::STARTUP_HEADER_LEN..) else { return settings };
    while let Ok(key) = pgwire::take_cstr(&mut params) {
        if key.is_empty() {
            break;
        }
        let Ok(value) = pgwire::take_cstr(&mut params) else { break };
        if key.eq_ignore_ascii_case(b"search_path") {
            settings.search_path_trusted &= value == b"public";
        } else if key.eq_ignore_ascii_case(b"standard_conforming_strings") {
            settings.escape_strings |= !is_on(value);
        } else if key.eq_ignore_ascii_case(b"options") {
            // `options` is a command line, not a value: `-c name=value`,
            // `--name=value` and shell quoting all spell the same assignment,
            // and which value each ends up with is not something the proxy can
            // read back reliably. A mention of either setting is therefore
            // taken as a move — the same conservative reading the in-session
            // scan gives an assignment it cannot evaluate.
            settings.search_path_trusted &= !mentions(value, b"search_path");
            settings.escape_strings |= mentions(value, b"standard_conforming_strings");
        }
    }
    settings
}

/// Whether a command line mentions a setting by name at all.
fn mentions(options: &[u8], setting: &[u8]) -> bool {
    options.windows(setting.len()).any(|window| window.eq_ignore_ascii_case(setting))
}

/// Whether a startup parameter turns a boolean setting on. The spellings are
/// [`crate::encrypt::is_on_value`]'s, so the connect-time reading of a setting
/// cannot drift from the in-session one. Anything else — a value that is not
/// even UTF-8 included — leaves the setting off as far as the rewrite is
/// concerned: a value the proxy cannot read is one it cannot keep assuming.
fn is_on(value: &[u8]) -> bool {
    std::str::from_utf8(value).is_ok_and(crate::encrypt::is_on_value)
}

/// Sends SSLRequest upstream and requires the `S` answer; a server that
/// refuses TLS fails the session (verify-full, no downgrade).
async fn request_upstream_tls(mut sock: TcpStream, addr: &str) -> Result<TcpStream, Error> {
    let mut request = 8i32.to_be_bytes().to_vec();
    request.extend_from_slice(&pgwire::SSL_REQUEST.to_be_bytes());
    sock.write_all(&request).await?;
    let mut answer = [0u8; 1];
    sock.read_exact(&mut answer).await?;
    if &answer != b"S" {
        return Err(Error::UpstreamTlsRefused { addr: addr.to_owned() });
    }
    Ok(sock)
}

/// Reads one startup-phase message (which has no type byte). Returns the full
/// message including its length field, or `None` on a clean pre-startup EOF.
///
/// The buffer is sized from the client's own length prefix, so the only thing
/// standing between an unauthenticated peer and a `vec![0u8; …]` of its
/// choosing is the bound [`pgwire::startup_body_len`] applies
/// ([`pgwire::MAX_STARTUP_MESSAGE_LEN`], not the 1 GiB frame limit) — which is
/// why that check runs before the allocation rather than after the read
/// (SEC-33).
async fn read_startup_message<S>(stream: &mut S) -> Result<Option<Vec<u8>>, Error>
where
    S: AsyncRead + Unpin,
{
    let mut len_field = [0u8; 4];
    match stream.read_exact(&mut len_field).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let body_len = pgwire::startup_body_len(len_field)?;
    let mut msg = vec![0u8; 4 + body_len];
    msg[..4].copy_from_slice(&len_field);
    stream.read_exact(&mut msg[4..]).await?;
    Ok(Some(msg))
}

/// Builds the header of a rewritten frame: `u8 type | i32 length`, where the
/// length counts itself but not the type byte — the same convention
/// [`pgwire::frame_body_len`] inverts on the way in, which is why the `+ 4`
/// appears here and the `- 4` appears there.
///
/// The length is *checked*, not cast: rewritten bodies are systematically
/// larger than what came in (hex-encoding a sealed BYTEA parameter roughly
/// doubles it), so a body just under the inbound limit can produce a
/// replacement over `i32::MAX`. An `as i32` there truncates silently in
/// release builds and puts a nonsensical length on the wire — the one thing
/// [`relay`] exists to prevent (SEC-15).
fn encode_frame_header(
    msg_type: u8,
    body_len: usize,
) -> Result<[u8; pgwire::FRAME_HEADER_LEN], Error> {
    let len = body_len
        .checked_add(4)
        .filter(|len| *len <= pgwire::MAX_MESSAGE_LEN)
        .and_then(|len| i32::try_from(len).ok())
        .ok_or(Error::FrameTooLarge {
            msg_type: msg_type as char,
            body_len,
            max: pgwire::MAX_MESSAGE_LEN,
        })?;
    let mut header = [0u8; pgwire::FRAME_HEADER_LEN];
    header[0] = msg_type;
    header[1..].copy_from_slice(&len.to_be_bytes());
    Ok(header)
}

/// The two writers one relay can reach. `forward` is its own direction;
/// `back` is the peer's, which is where a [`FrameAction::Reply`] goes so the
/// sender can be answered without forwarding anything. Both are shared with
/// the opposite relay, which is why they are behind a mutex — whole frames
/// are written under the lock, so the two directions never interleave inside
/// a message.
struct Writers<W, B> {
    forward: Arc<Mutex<W>>,
    back: Arc<Mutex<B>>,
}

/// Copies framed messages from `reader` to `writers.forward` until EOF at a
/// frame boundary, passing each frame through `transform`. EOF mid-frame is
/// an error; frames with invalid lengths or failing transforms abort the
/// session rather than desyncing the relay or leaking ciphertext.
///
/// `shutdown` is observed *only between frames*: a rewritten frame is a
/// header write followed by a body write, and stopping between the two would
/// hand the peer a header promising bytes that never arrive (CONC-6).
///
/// There is deliberately no idle timeout. A pgwire session is idle whenever
/// the application is between statements, and a pooled connection is
/// legitimately idle for hours; the relay cannot tell that apart from an
/// abandoned socket, so an idle reaper would drop working connections. The
/// exhaustion risk is bounded at admission instead (`max_sessions` in
/// `main::accept_loop`), before the relay by the startup deadline, and inside
/// it by [`Direction::limit`] — which is what keeps a peer the backend has not
/// authenticated from sizing this loop's buffer to the authenticated-traffic
/// limit (SEC-33).
async fn relay<R, W, B, T>(
    mut reader: R,
    writers: Writers<W, B>,
    direction: Direction,
    mut transform: T,
    mut shutdown: ShutdownRx,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    B: AsyncWrite + Unpin,
    T: FnMut(u8, &[u8]) -> Result<FrameAction, Error>,
{
    let Writers { forward, back } = writers;
    let Direction { name: direction, limit } = direction;
    let mut header = [0u8; pgwire::FRAME_HEADER_LEN];
    let mut body = Vec::new();
    loop {
        // `read_exact` is not cancel-safe, but the only thing that cancels it
        // is shutdown, which closes the connection anyway — and it holds no
        // half-written frame, since writes happen further down the loop.
        let next = tokio::select! {
            biased;
            read = reader.read_exact(&mut header) => read,
            _ = shutdown.changed() => {
                tracing::debug!(direction, "shutdown at frame boundary; closing relay");
                forward.lock().await.shutdown().await.ok();
                return Ok(());
            }
        };
        match next {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                forward.lock().await.shutdown().await.ok();
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        let (msg_type, body_len) = pgwire::frame_body_len(&header).map_err(|e| {
            tracing::warn!(direction, error = %e, "aborting desynced relay");
            e
        })?;
        // Before the `resize` below, which is the allocation this bound exists
        // to deny an unauthenticated peer. Under `BodyLimit::Full` the check is
        // dead weight — `frame_body_len` already refused anything over
        // `MAX_MESSAGE_LEN` — so this can only fire pre-authentication.
        let max_body = limit.max_body();
        if body_len > max_body {
            let e =
                Error::PreAuthFrameTooLarge { msg_type: msg_type as char, body_len, max: max_body };
            tracing::warn!(direction, error = %e, "refusing a pre-authentication frame");
            return Err(e);
        }
        body.resize(body_len, 0);
        reader.read_exact(&mut body).await?;
        tracing::trace!(direction, msg_type = %(msg_type as char), body_len, "relayed frame");
        match transform(msg_type, &body).map_err(|e| {
            tracing::error!(direction, msg_type = %(msg_type as char), error = %e, "transform failed; closing session");
            e
        })? {
            FrameAction::Replace(new_body) => {
                let new_header = encode_frame_header(msg_type, new_body.len()).map_err(|e| {
                    tracing::error!(direction, error = %e, "rewritten frame too large; closing session");
                    e
                })?;
                let mut writer = forward.lock().await;
                writer.write_all(&new_header).await?;
                writer.write_all(&new_body).await?;
            }
            FrameAction::Relay => {
                let mut writer = forward.lock().await;
                writer.write_all(&header).await?;
                writer.write_all(&body).await?;
            }
            FrameAction::Reply(frames) => {
                tracing::debug!(
                    direction,
                    msg_type = %(msg_type as char),
                    answered = !frames.is_empty(),
                    "frame withheld from the peer"
                );
                if !frames.is_empty() {
                    back.lock().await.write_all(&frames).await?;
                }
            }
            FrameAction::RefuseAndClose(frames) => {
                tracing::debug!(
                    direction,
                    msg_type = %(msg_type as char),
                    "result refused; answering the receiver and closing the session"
                );
                // The answer goes out and is flushed before either half is shut
                // down: the client has to still be able to read it.
                {
                    let mut writer = forward.lock().await;
                    writer.write_all(&frames).await?;
                    writer.flush().await?;
                    writer.shutdown().await.ok();
                }
                // Closing the peer's half is what aborts the batch upstream —
                // the backend rolls back the implicit transaction rather than
                // committing statements behind the error just sent.
                back.lock().await.shutdown().await.ok();
                return Ok(());
            }
        }
        // Give a one-off large frame's buffer back instead of reserving it for
        // the life of the session; `resize` re-grows it if another one comes.
        if body.capacity() > RELAY_BUFFER_RETAIN {
            body.clear();
            body.shrink_to(RELAY_BUFFER_RETAIN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn frame(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![msg_type];
        out.extend_from_slice(&(4 + body.len() as i32).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn ssl_request() -> Vec<u8> {
        let mut msg = 8i32.to_be_bytes().to_vec();
        msg.extend_from_slice(&pgwire::SSL_REQUEST.to_be_bytes());
        msg
    }

    fn startup_v3() -> Vec<u8> {
        let params = b"user\0test\0\0";
        let mut msg = ((8 + params.len()) as i32).to_be_bytes().to_vec();
        msg.extend_from_slice(&pgwire::PROTOCOL_V3.to_be_bytes());
        msg.extend_from_slice(params);
        msg
    }

    /// Long enough that no test hits it by accident; the deadline itself is
    /// exercised by `idle_client_is_dropped_at_the_startup_deadline`.
    const TEST_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

    fn plain_ctx(upstream_addr: &str) -> SessionContext {
        SessionContext {
            upstream_addr: upstream_addr.to_owned(),
            tls: Arc::new(
                TlsContext::from_config(&Config::default().validated().unwrap()).unwrap(),
            ),
            rows: None,
            writes: None,
            startup_timeout: TEST_STARTUP_TIMEOUT,
        }
    }

    /// A shutdown channel that never fires. The sender is returned because
    /// dropping it *is* a shutdown signal — it must outlive the relay.
    fn no_shutdown() -> (watch::Sender<bool>, ShutdownRx) {
        watch::channel(false)
    }

    /// Self-signed cert for `localhost`, written as PEM files.
    fn test_cert(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        // Written the way an operator has to write it: validation refuses a
        // `[tls.downstream] key` readable beyond its owner (SEC-29), and every
        // `TlsContext` is built from a validated config.
        #[cfg(unix)]
        std::fs::set_permissions(&key_path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        (cert_path, key_path)
    }

    /// Fake plaintext upstream: reads the startup message, answers with an
    /// `R` frame, echoes the startup back through the task handle.
    async fn spawn_fake_upstream() -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut len_field = [0u8; 4];
            sock.read_exact(&mut len_field).await.unwrap();
            let mut startup = vec![0u8; i32::from_be_bytes(len_field) as usize];
            startup[..4].copy_from_slice(&len_field);
            sock.read_exact(&mut startup[4..]).await.unwrap();
            sock.write_all(&frame(b'R', &0i32.to_be_bytes())).await.unwrap();
            sock.shutdown().await.unwrap();
            startup
        });
        (addr, task)
    }

    /// A writer both a relay and its test can look at.
    fn sink() -> Arc<Mutex<Vec<u8>>> {
        Arc::new(Mutex::new(Vec::new()))
    }

    #[tokio::test]
    async fn relay_rewrites_transformed_frames_and_lengths() {
        let (_shutdown_tx, shutdown) = no_shutdown();
        let mut input = frame(b'D', b"old");
        input.extend_from_slice(&frame(b'Z', b"I"));
        let (output, back) = (sink(), sink());
        relay(
            input.as_slice(),
            Writers { forward: output.clone(), back: back.clone() },
            Direction::unbounded("test"),
            |msg_type, body| {
                assert!(matches!(msg_type, b'D' | b'Z'));
                Ok(if msg_type == b'D' && body == b"old" {
                    FrameAction::Replace(b"rewritten".to_vec())
                } else {
                    FrameAction::Relay
                })
            },
            shutdown,
        )
        .await
        .unwrap();

        let mut expected = frame(b'D', b"rewritten");
        expected.extend_from_slice(&frame(b'Z', b"I"));
        assert_eq!(*output.lock().await, expected);
        assert!(back.lock().await.is_empty());
    }

    /// A refused frame reaches neither peer; the answer goes back the way it
    /// came, and the relay stays in sync for the frames that follow.
    #[tokio::test]
    async fn relay_answers_the_sender_without_forwarding() {
        let (_shutdown_tx, shutdown) = no_shutdown();
        let mut input = frame(b'Q', b"refuse me");
        input.extend_from_slice(&frame(b'Q', b"fine"));
        let (output, back) = (sink(), sink());
        relay(
            input.as_slice(),
            Writers { forward: output.clone(), back: back.clone() },
            Direction::unbounded("test"),
            |_, body| {
                Ok(if body == b"refuse me" {
                    FrameAction::Reply(frame(b'E', b"nope"))
                } else {
                    FrameAction::Relay
                })
            },
            shutdown,
        )
        .await
        .unwrap();

        assert_eq!(*output.lock().await, frame(b'Q', b"fine"));
        assert_eq!(*back.lock().await, frame(b'E', b"nope"));
    }

    /// The read path's refusal: the offending frame is withheld from the
    /// receiver and answered in its place, in the same direction — and then the
    /// relay stops, because everything queued behind it upstream has to stop
    /// too.
    #[tokio::test]
    async fn relay_answers_a_refused_frame_and_then_closes() {
        let (_shutdown_tx, shutdown) = no_shutdown();
        let mut input = frame(b'D', b"refuse me");
        // Whatever the backend was still sending for this batch. None of it may
        // reach the client, and the relay must not resume to read it.
        input.extend_from_slice(&frame(b'D', b"more rows"));
        input.extend_from_slice(&frame(b'Z', b"I"));
        let (output, back) = (sink(), sink());
        relay(
            input.as_slice(),
            Writers { forward: output.clone(), back: back.clone() },
            Direction::unbounded("test"),
            |_, body| {
                Ok(match body {
                    b"refuse me" => FrameAction::RefuseAndClose(frame(b'E', b"nope")),
                    _ => FrameAction::Relay,
                })
            },
            shutdown,
        )
        .await
        .unwrap();

        assert_eq!(
            *output.lock().await,
            frame(b'E', b"nope"),
            "the client gets the refusal and nothing that followed it"
        );
        assert!(back.lock().await.is_empty(), "nothing goes back to the sender");
    }

    /// The other half of a refusal: the direction that refused is done, but
    /// the opposite one is parked reading from a client that is under no
    /// obligation to close its own write half. Waiting for it — which
    /// `try_join!` did — kept the session, both descriptors and any buffered
    /// frame alive until the client left or TCP timed out.
    #[tokio::test(start_paused = true)]
    async fn a_refused_session_does_not_wait_on_the_clients_write_half() {
        let (_shutdown_tx, shutdown) = no_shutdown();
        let refused = frame(b'D', b"refuse me");
        let answered = sink();
        let refusing = relay(
            refused.as_slice(),
            Writers { forward: answered.clone(), back: sink() },
            Direction::unbounded("upstream->client"),
            |_, _| Ok(FrameAction::RefuseAndClose(frame(b'E', b"nope"))),
            shutdown.clone(),
        );
        // An open, silent socket is what a client holding its write half open
        // looks like from here: the read never completes and never EOFs.
        let (_client, client_r) = tokio::io::duplex(64);
        let stalled = relay(
            client_r,
            Writers { forward: sink(), back: sink() },
            Direction::unbounded("client->upstream"),
            |_, _| Ok(FrameAction::Relay),
            shutdown,
        );

        join_relays(stalled, refusing).await.unwrap();
        assert_eq!(
            *answered.lock().await,
            frame(b'E', b"nope"),
            "the refusal still reaches the client before the session ends"
        );
    }

    /// The drain is a bound, not a cancel: a direction still carrying the
    /// results of the client's last statement runs to completion, and its
    /// outcome is the session's.
    #[tokio::test(start_paused = true)]
    async fn the_surviving_direction_finishes_inside_the_drain_window() {
        let ended = std::future::ready(Ok(()));
        let still_relaying = async {
            tokio::time::sleep(RELAY_DRAIN_TIMEOUT / 2).await;
            Err(Error::Wire(dbsec_core::Error::Decrypt))
        };
        assert!(matches!(
            join_relays(ended, still_relaying).await,
            Err(Error::Wire(dbsec_core::Error::Decrypt))
        ));
    }

    /// A failure in the direction that ended first is the session's error, and
    /// nothing the other one does — including never finishing — replaces it.
    #[tokio::test(start_paused = true)]
    async fn the_first_directions_failure_is_the_sessions_error() {
        let failed = std::future::ready(Err(Error::PlaintextRejected));
        let never = std::future::pending::<Result<(), Error>>();
        assert!(matches!(join_relays(never, failed).await, Err(Error::PlaintextRejected)));
    }

    #[tokio::test]
    async fn relay_fails_closed_on_transform_error() {
        let (_shutdown_tx, shutdown) = no_shutdown();
        let input = frame(b'D', b"boom");
        let (output, back) = (sink(), sink());
        relay(
            input.as_slice(),
            Writers { forward: output.clone(), back },
            Direction::unbounded("test"),
            |_, _| Err(Error::Wire(dbsec_core::Error::Decrypt)),
            shutdown,
        )
        .await
        .unwrap_err();
        assert!(output.lock().await.is_empty());
    }

    /// The refusal has to happen *before* the buffer is sized, so the input is
    /// nothing but the four-byte length prefix: a reader that allocated and
    /// then tried to fill 1 GiB would fail with `UnexpectedEof` instead.
    #[tokio::test]
    async fn oversized_startup_length_is_refused_before_anything_is_allocated() {
        for len in [pgwire::MAX_STARTUP_MESSAGE_LEN + 1, pgwire::MAX_MESSAGE_LEN, i32::MAX as usize]
        {
            let len_field = (len as i32).to_be_bytes();
            let result = read_startup_message(&mut &len_field[..]).await;
            assert!(
                matches!(
                    result,
                    Err(Error::Wire(dbsec_core::Error::StartupMessageTooLarge {
                        max: pgwire::MAX_STARTUP_MESSAGE_LEN,
                        ..
                    }))
                ),
                "length {len} should be refused without reading a body, got {result:?}"
            );
        }
    }

    /// The window TASK-0076 left open: the startup packet is forwarded, so its
    /// 16 KiB cap no longer applies, but the backend has not accepted the
    /// client either — so the 1 GiB frame limit, which is Postgres parity for
    /// *authenticated* traffic, must not apply yet either (SEC-33). The
    /// oversized frame is nothing but its header, so a relay that sized the
    /// buffer first would fail with `UnexpectedEof` rather than with the bound.
    #[tokio::test]
    async fn an_oversized_frame_before_authentication_is_refused() {
        let (_shutdown_tx, shutdown) = no_shutdown();
        // What a client legitimately sends here: a SASL response, a few
        // hundred bytes. It relays, and then the oversized one does not.
        let mut input = frame(b'p', b"n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL");
        input.push(b'Q');
        input.extend_from_slice(&((4 + pgwire::MAX_PRE_AUTH_MESSAGE_LEN + 1) as i32).to_be_bytes());
        let relayed = input[..input.len() - pgwire::FRAME_HEADER_LEN].to_vec();

        let output = sink();
        let result = relay(
            input.as_slice(),
            Writers { forward: output.clone(), back: sink() },
            Direction {
                name: "client->upstream",
                limit: BodyLimit::UntilAuthenticated(Arc::new(AtomicBool::new(false))),
            },
            |_, _| Ok(FrameAction::Relay),
            shutdown,
        )
        .await;

        assert!(
            matches!(
                result,
                Err(Error::PreAuthFrameTooLarge {
                    msg_type: 'Q',
                    max: pgwire::MAX_PRE_AUTH_MESSAGE_LEN,
                    ..
                })
            ),
            "got {result:?}"
        );
        assert_eq!(
            *output.lock().await,
            relayed,
            "the authentication frame in front of it still went through"
        );
    }

    /// The other half of the bound, and the one it would be a regression to
    /// get wrong: once the backend has answered AuthenticationOk the limit is
    /// the 1 GiB Postgres parity TASK-0009 settled on, unchanged.
    #[tokio::test]
    async fn authentication_restores_the_full_frame_limit() {
        let (_shutdown_tx, shutdown) = no_shutdown();
        let authenticated = Arc::new(AtomicBool::new(false));
        // Exactly what the upstream→client direction does with the backend's
        // verdict, before forwarding it.
        note_authentication(b'R', &0i32.to_be_bytes(), &authenticated);
        assert_eq!(
            BodyLimit::UntilAuthenticated(authenticated.clone()).max_body(),
            pgwire::MAX_MESSAGE_LEN
        );

        // A frame the pre-authentication bound would have refused, relayed
        // whole now that it no longer applies.
        let big = frame(b'Q', &vec![b'x'; pgwire::MAX_PRE_AUTH_MESSAGE_LEN + 1]);
        let output = sink();
        relay(
            big.as_slice(),
            Writers { forward: output.clone(), back: sink() },
            Direction {
                name: "client->upstream",
                limit: BodyLimit::UntilAuthenticated(authenticated),
            },
            |_, _| Ok(FrameAction::Relay),
            shutdown,
        )
        .await
        .unwrap();
        assert_eq!(*output.lock().await, big);
    }

    /// `'R'` is the whole authentication exchange, not just its verdict, so the
    /// bound has to key on the request code rather than on the message type.
    #[test]
    fn only_authentication_ok_lifts_the_pre_authentication_bound() {
        let authenticated = AtomicBool::new(false);
        // 3 cleartext, 5 MD5, 10 SASL, 11 SASL continue, 12 SASL final: the
        // exchange still in progress.
        for code in [3i32, 5, 10, 11, 12] {
            note_authentication(b'R', &code.to_be_bytes(), &authenticated);
            assert!(
                !authenticated.load(Ordering::Relaxed),
                "'R' request code {code} is not an acceptance"
            );
        }
        // An ErrorResponse whose body happens to start with four zero bytes,
        // and a truncated 'R' that carries no request code at all.
        note_authentication(b'E', &0i32.to_be_bytes(), &authenticated);
        note_authentication(b'R', b"ab", &authenticated);
        assert!(!authenticated.load(Ordering::Relaxed));

        note_authentication(b'R', &0i32.to_be_bytes(), &authenticated);
        assert!(authenticated.load(Ordering::Relaxed), "AuthenticationOk lifts the bound");
    }

    /// The cap only has to be above what a real driver sends. A startup packet
    /// carrying a long `options=-c …` is the largest legitimate shape there is,
    /// and it still goes through untouched.
    #[tokio::test]
    async fn a_startup_message_with_a_large_options_parameter_still_reads() {
        let mut params = b"user\0test\0options\0".to_vec();
        params.extend(std::iter::repeat_n(b'x', 8 * 1024));
        params.extend_from_slice(b"\0\0");
        let mut msg = ((8 + params.len()) as i32).to_be_bytes().to_vec();
        msg.extend_from_slice(&pgwire::PROTOCOL_V3.to_be_bytes());
        msg.extend_from_slice(&params);
        assert!(msg.len() <= pgwire::MAX_STARTUP_MESSAGE_LEN, "fixture must stay under the cap");

        let read = read_startup_message(&mut msg.as_slice()).await.unwrap();
        assert_eq!(read.as_deref(), Some(msg.as_slice()));
    }

    /// A startup message carrying `params` as its parameter section.
    fn startup(params: &[u8]) -> Vec<u8> {
        let mut msg = ((8 + params.len()) as i32).to_be_bytes().to_vec();
        msg.extend_from_slice(&pgwire::PROTOCOL_V3.to_be_bytes());
        msg.extend_from_slice(params);
        msg
    }

    #[test]
    fn startup_parameters_reveal_a_moved_search_path() {
        let trusted = |params: &[u8]| startup_settings(&startup(params)).search_path_trusted;
        assert!(trusted(b"user\0test\0\0"));
        assert!(trusted(b"search_path\0public\0\0"));
        assert!(!trusted(b"search_path\0tenant7\0\0"));
        assert!(!trusted(b"options\0-c search_path=tenant7\0\0"));
        // The server resolves a setting name case-insensitively, so a startup
        // packet can move `search_path` without spelling it in lower case.
        assert!(!trusted(b"SEARCH_PATH\0tenant7\0\0"));
        assert!(!trusted(b"options\0-c Search_Path=tenant7\0\0"));
        // A cancel request has no parameter section at all.
        assert!(trusted(b""));
    }

    /// The other setting the rewrite depends on, reachable by the same two
    /// spellings. Missed here, the divergence it causes is silent: from the
    /// first statement onwards a backslash in an ordinary literal means one
    /// thing to PostgreSQL and another to the proxy's parser.
    #[test]
    fn startup_parameters_reveal_standard_conforming_strings_turned_off() {
        let escapes = |params: &[u8]| startup_settings(&startup(params)).escape_strings;
        assert!(!escapes(b"user\0test\0\0"));
        assert!(!escapes(b"standard_conforming_strings\0on\0\0"));
        // Every spelling of boolean true leaves the setting where the rewrite
        // already assumes it is.
        for on in [&b"on"[..], b"ON", b"true", b"t", b"yes", b"y", b"1"] {
            let mut params = b"standard_conforming_strings\0".to_vec();
            params.extend_from_slice(on);
            params.extend_from_slice(b"\0\0");
            assert!(!escapes(&params), "{}", String::from_utf8_lossy(on));
        }
        assert!(escapes(b"standard_conforming_strings\0off\0\0"));
        assert!(escapes(b"STANDARD_CONFORMING_STRINGS\0off\0\0"));
        assert!(escapes(b"options\0-c standard_conforming_strings=off\0\0"));
        // A value the proxy cannot evaluate is one it cannot keep assuming.
        assert!(escapes(b"standard_conforming_strings\0\0\0"));
        assert!(!escapes(b""));
    }

    /// The two settings are read out of one pass, so a packet that moves both
    /// must not have either reading swallow the other.
    #[test]
    fn a_startup_packet_can_move_both_settings_at_once() {
        let settings = startup_settings(&startup(
            b"options\0-c search_path=tenant7 -c \
                standard_conforming_strings=off\0user\0test\0\0",
        ));
        assert!(!settings.search_path_trusted);
        assert!(settings.escape_strings);
    }

    /// The write path's copy handling hangs off a frame only the read
    /// direction ever sees, so the wiring is part of the fix rather than
    /// plumbing around it: without this call a real `CopyData` reads as a
    /// stray, and the Sync the backend is ignoring stays queued to absorb the
    /// next batch's ReadyForQuery.
    #[test]
    fn the_read_direction_records_the_backends_copy_and_transaction_state() {
        use crate::portal::RowSource;

        let portals = SessionPortals::new();
        let tx_status = AtomicU8::new(TX_IDLE);
        note_backend_state(b'Z', b"T", &tx_status, &portals);
        assert_eq!(
            tx_status.load(Ordering::Relaxed),
            b'T',
            "a refusal's synthesized ReadyForQuery reports this status"
        );

        // Execute/Sync, pipelined before the CopyInResponse came back: the
        // Sync the backend ignores while it is in copy-in mode.
        portals.expect_execute(b"p").unwrap();
        portals.expect_batch().unwrap();
        // No CopyInResponse recorded yet, so this one is a stray and the
        // marker has to survive it.
        portals.copy_data(b'd');
        note_backend_state(b'G', b"", &tx_status, &portals);
        portals.copy_data(b'd');

        // CopyDone's Sync, and the batch pipelined behind it.
        portals.expect_batch().unwrap();
        portals.expect_execute(b"next").unwrap();
        portals.execute_answered();
        portals.batch_answered();
        assert!(
            matches!(portals.row_source(), RowSource::Undescribed),
            "the ignored Sync must have been dropped, leaving the next batch's Execute in front"
        );
    }

    #[test]
    fn frame_header_writes_each_field_once() {
        assert_eq!(encode_frame_header(b'D', 9).unwrap(), [b'D', 0, 0, 0, 13]);
        assert_eq!(encode_frame_header(b'Z', 0).unwrap(), [b'Z', 0, 0, 0, 4]);
        // The header must round-trip through the parser that reads it.
        let header = encode_frame_header(b'B', 42).unwrap();
        assert_eq!(pgwire::frame_body_len(&header).unwrap(), (b'B', 42));
    }

    #[test]
    fn frame_header_rejects_oversized_bodies_instead_of_truncating() {
        for body_len in [pgwire::MAX_MESSAGE_LEN, i32::MAX as usize, usize::MAX] {
            assert!(
                matches!(encode_frame_header(b'D', body_len), Err(Error::FrameTooLarge { .. })),
                "body_len {body_len} should be rejected"
            );
        }
        // The largest body that still fits, for the boundary either side.
        let header = encode_frame_header(b'D', pgwire::MAX_MESSAGE_LEN - 4).unwrap();
        assert_eq!(pgwire::frame_body_len(&header).unwrap(), (b'D', pgwire::MAX_MESSAGE_LEN - 4));
    }

    #[tokio::test]
    async fn relay_fails_closed_on_an_oversized_rewritten_body() {
        let (_shutdown_tx, shutdown) = no_shutdown();
        let input = frame(b'D', b"small");
        let (output, back) = (sink(), sink());
        let result = relay(
            input.as_slice(),
            Writers { forward: output.clone(), back },
            Direction::unbounded("test"),
            |_, _| {
                // Zeroed pages: the buffer is never written to and the header
                // check rejects it before any I/O, so this costs address
                // space rather than resident memory.
                Ok(FrameAction::Replace(vec![0u8; pgwire::MAX_MESSAGE_LEN + 1]))
            },
            shutdown,
        )
        .await;
        assert!(matches!(result, Err(Error::FrameTooLarge { .. })));
        assert!(output.lock().await.is_empty(), "no corrupt header may reach the wire");
    }

    #[tokio::test]
    async fn relay_stops_at_a_frame_boundary_on_shutdown() {
        let (shutdown_tx, shutdown) = no_shutdown();
        let (mut feed, reader) = tokio::io::duplex(1024);
        let (writer, mut peer) = tokio::io::duplex(1024);
        let writers = Writers { forward: Arc::new(Mutex::new(writer)), back: sink() };
        let relaying = tokio::spawn(async move {
            relay(
                reader,
                writers,
                Direction::unbounded("test"),
                |_, _| Ok(FrameAction::Relay),
                shutdown,
            )
            .await
        });

        // Reading the whole frame back proves the relay is parked on the next
        // header read, not mid-write, when the signal arrives.
        feed.write_all(&frame(b'Z', b"I")).await.unwrap();
        let mut relayed = vec![0u8; pgwire::FRAME_HEADER_LEN + 1];
        peer.read_exact(&mut relayed).await.unwrap();
        assert_eq!(relayed, frame(b'Z', b"I"));

        shutdown_tx.send(true).unwrap();
        timeout(Duration::from_secs(5), relaying).await.unwrap().unwrap().unwrap();
    }

    #[tokio::test]
    async fn idle_client_is_dropped_at_the_startup_deadline() {
        let (_shutdown_tx, shutdown) = no_shutdown();
        let ctx = SessionContext {
            startup_timeout: Duration::from_millis(100),
            // Never reached: the client sends nothing at all.
            ..plain_ctx("127.0.0.1:1")
        };
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let session = tokio::spawn(async move {
            let (sock, _) = proxy.accept().await.unwrap();
            run(sock, &ctx, shutdown).await
        });

        let _client = TcpStream::connect(proxy_addr).await.unwrap();
        let result = timeout(Duration::from_secs(5), session).await.unwrap().unwrap();
        assert!(matches!(result, Err(Error::StartupTimeout { .. })));
    }

    #[tokio::test]
    async fn session_negotiates_ssl_refusal_and_relays() {
        let (_shutdown_tx, shutdown) = no_shutdown();
        let (upstream_addr, upstream_task) = spawn_fake_upstream().await;

        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let session = tokio::spawn(async move {
            let (sock, _) = proxy.accept().await.unwrap();
            run(sock, &plain_ctx(&upstream_addr), shutdown).await
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&ssl_request()).await.unwrap();
        let mut answer = [0u8; 1];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"N");

        let startup = startup_v3();
        client.write_all(&startup).await.unwrap();

        let mut auth = vec![0u8; 9];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, frame(b'R', &0i32.to_be_bytes()));

        assert_eq!(upstream_task.await.unwrap(), startup);
        client.shutdown().await.unwrap();
        session.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn downstream_tls_handshakes_and_rejects_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = test_cert(dir.path());
        let (upstream_addr, upstream_task) = spawn_fake_upstream().await;

        let config: Config = toml::from_str(&format!(
            "[tls.downstream]\ncert = {:?}\nkey = {:?}\n",
            cert_path, key_path
        ))
        .unwrap();
        let config = config.validated().unwrap();
        let (_shutdown_tx, shutdown) = no_shutdown();
        let first_ctx = SessionContext {
            upstream_addr: "127.0.0.1:1".to_owned(),
            tls: Arc::new(TlsContext::from_config(&config).unwrap()),
            rows: None,
            writes: None,
            startup_timeout: TEST_STARTUP_TIMEOUT,
        };
        let second_ctx = SessionContext {
            upstream_addr,
            tls: Arc::new(TlsContext::from_config(&config).unwrap()),
            rows: None,
            writes: None,
            startup_timeout: TEST_STARTUP_TIMEOUT,
        };

        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let sessions = tokio::spawn(async move {
            // First connection: plaintext startup → rejected.
            let (sock, _) = proxy.accept().await.unwrap();
            let plaintext_result = run(sock, &first_ctx, shutdown.clone()).await;
            // Second connection: TLS handshake, then relayed startup.
            let (sock, _) = proxy.accept().await.unwrap();
            let tls_result = run(sock, &second_ctx, shutdown).await;
            (plaintext_result, tls_result)
        });

        // Plaintext client is refused before anything reaches an upstream.
        let mut plain = TcpStream::connect(proxy_addr).await.unwrap();
        plain.write_all(&startup_v3()).await.unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(plain.read(&mut buf).await.unwrap(), 0);
        drop(plain);

        // TLS client: SSLRequest → 'S' → handshake → startup relayed.
        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls::pki_types::CertificateDer::pem_file_iter(&cert_path).unwrap() {
            roots.add(cert.unwrap()).unwrap();
        }
        let client_config = Arc::new(
            rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth(),
        );
        let mut sock = TcpStream::connect(proxy_addr).await.unwrap();
        sock.write_all(&ssl_request()).await.unwrap();
        let mut answer = [0u8; 1];
        sock.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"S");
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut client = connector.connect(name, sock).await.unwrap();

        let startup = startup_v3();
        client.write_all(&startup).await.unwrap();
        let mut auth = vec![0u8; 9];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, frame(b'R', &0i32.to_be_bytes()));

        assert_eq!(upstream_task.await.unwrap(), startup);
        client.shutdown().await.unwrap();
        let (plaintext_result, tls_result) = sessions.await.unwrap();
        assert!(matches!(plaintext_result, Err(Error::PlaintextRejected)));
        tls_result.unwrap();
    }

    #[tokio::test]
    async fn upstream_tls_negotiates_and_refusal_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = test_cert(dir.path());

        // Fake TLS upstream: answers 'S', handshakes, reads startup, replies.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap().to_string();
        use rustls::pki_types::pem::PemObject;
        let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_file_iter(&cert_path)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_file(&key_path).unwrap();
        let upstream_task = tokio::spawn(async move {
            let server_config = Arc::new(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .unwrap(),
            );
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 8];
            sock.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[4..], pgwire::SSL_REQUEST.to_be_bytes());
            sock.write_all(b"S").await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let mut tls_sock = acceptor.accept(sock).await.unwrap();
            let mut len_field = [0u8; 4];
            tls_sock.read_exact(&mut len_field).await.unwrap();
            let mut startup = vec![0u8; i32::from_be_bytes(len_field) as usize];
            startup[..4].copy_from_slice(&len_field);
            tls_sock.read_exact(&mut startup[4..]).await.unwrap();
            tls_sock.write_all(&frame(b'R', &0i32.to_be_bytes())).await.unwrap();
            tls_sock.shutdown().await.unwrap();
            startup
        });

        let config: Config = toml::from_str(&format!(
            "upstream = \"{upstream_addr}\"\n\n[tls.upstream]\nca = {cert_path:?}\nhostname = \"localhost\"\n",
        ))
        .unwrap();
        let config = config.validated().unwrap();
        let (_shutdown_tx, shutdown) = no_shutdown();
        let ctx = SessionContext {
            upstream_addr: config.config.upstream.clone(),
            tls: Arc::new(TlsContext::from_config(&config).unwrap()),
            rows: None,
            writes: None,
            startup_timeout: TEST_STARTUP_TIMEOUT,
        };

        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let relayed_shutdown = shutdown.clone();
        let session = tokio::spawn(async move {
            let (sock, _) = proxy.accept().await.unwrap();
            run(sock, &ctx, relayed_shutdown).await
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let startup = startup_v3();
        client.write_all(&startup).await.unwrap();
        let mut auth = vec![0u8; 9];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, frame(b'R', &0i32.to_be_bytes()));
        assert_eq!(upstream_task.await.unwrap(), startup);
        client.shutdown().await.unwrap();
        session.await.unwrap().unwrap();

        // An upstream that answers 'N' fails the session (no downgrade).
        let refusing = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refusing_addr = refusing.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut sock, _) = refusing.accept().await.unwrap();
            let mut request = [0u8; 8];
            sock.read_exact(&mut request).await.unwrap();
            sock.write_all(b"N").await.unwrap();
        });
        let config: Config = toml::from_str(&format!(
            "upstream = \"{refusing_addr}\"\n\n[tls.upstream]\nca = {cert_path:?}\nhostname = \"localhost\"\n",
        ))
        .unwrap();
        let config = config.validated().unwrap();
        let ctx = SessionContext {
            upstream_addr: config.config.upstream.clone(),
            tls: Arc::new(TlsContext::from_config(&config).unwrap()),
            rows: None,
            writes: None,
            startup_timeout: TEST_STARTUP_TIMEOUT,
        };
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let session = tokio::spawn(async move {
            let (sock, _) = proxy.accept().await.unwrap();
            run(sock, &ctx, shutdown).await
        });
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&startup_v3()).await.unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(client.read(&mut buf).await.unwrap(), 0);
        assert!(matches!(session.await.unwrap(), Err(Error::UpstreamTlsRefused { .. })));
    }
}
