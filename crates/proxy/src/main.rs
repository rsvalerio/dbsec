//! dbsec: transparent PostgreSQL proxy for field-level encryption.
//! Frame-aware relay with optional TLS on both hops and transparent
//! decryption of configured columns on the read path. See plans/PLAN.md.

mod columns;
mod config;
mod encrypt;
mod portal;
mod resolve;
mod rows;
mod session;
mod tls;
mod vault;

use std::future::Future;
use std::io::{ErrorKind, IsTerminal};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dbsec_core::keys::FileKeySource;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use crate::config::{Config, KeySourceConfig, ValidatedConfig};
use crate::rows::RowContext;
use crate::session::{SessionContext, ShutdownRx};
use crate::tls::TlsContext;

/// How long shutdown waits for live sessions to reach a frame boundary before
/// the remainder are aborted.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline for a single network step the proxy initiates itself: the data
/// path's upstream connect ([`session`]) and the startup control
/// connection's connect and per-column lookup ([`resolve`]). One constant so
/// no proxy-initiated call can end up unbounded because its module happened
/// not to define one (ASYNC-6).
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Pause after an `accept()` failure that is not per-connection, so the loop
/// cannot spin at 100% CPU re-failing while descriptors are unavailable.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Consecutive `accept()` failures tolerated before the listener is presumed
/// broken and `serve` gives up. The backstop for listener faults that stable
/// `ErrorKind`s cannot name.
const MAX_CONSECUTIVE_ACCEPT_ERRORS: u32 = 32;

/// Minimum gap between "session limit reached" log lines. A connection burst
/// is exactly the case where per-connection logging would itself be the load.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading config {path}: {source}")]
    ConfigRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing config {path}: {source}")]
    ConfigParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("connecting to upstream {addr}: timed out")]
    ConnectTimeout { addr: String },
    #[error("client startup did not complete within {timeout:?}")]
    StartupTimeout { timeout: Duration },
    #[error("downstream TLS handshake did not complete within {timeout:?}")]
    TlsHandshakeTimeout { timeout: Duration },
    #[error("rewritten '{msg_type}' frame body is {body_len} bytes, over the {max} byte limit")]
    FrameTooLarge { msg_type: char, body_len: usize, max: usize },
    #[error("tls config: {0}")]
    TlsConfig(String),
    #[error("client sent a plaintext startup but TLS is required")]
    PlaintextRejected,
    #[error("upstream {addr} refused TLS")]
    UpstreamTlsRefused { addr: String },
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("binding listen address {addr}: {source}")]
    Listen {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("vault: {0}")]
    Vault(String),
    #[error("control connection: {0}")]
    Control(String),
    #[error("control connection to {host}: no response within {timeout:?}")]
    ControlTimeout { host: String, timeout: Duration },
    #[error("configured column {table}.{column} does not exist")]
    ColumnNotFound { table: String, column: String },
    #[error("a rewritten statement did not re-parse to the same SQL; refusing to send it")]
    RewriteDiverged,
    #[error("client's {what} name is {len} bytes, over the {max} byte limit")]
    NameTooLong { what: &'static str, len: usize, max: usize },
    #[error("session reached its limit of {limit} {what}")]
    SessionLimit { what: &'static str, limit: usize },
    #[error(
        "placeholder ${placeholder} feeds two protected positions that need different values; \
         refusing to rewrite the statement"
    )]
    ConflictingParameter { placeholder: usize },
    #[error(
        "a DataRow arrived for a portal the server never described; refusing to relay columns \
         that may be protected"
    )]
    UndescribedRow,
    #[error(
        "result column {column} of table {table_oid} is named like a protected column but is not \
         in the resolved column map; the table may have been recreated since startup"
    )]
    StaleColumnMap { column: String, table_oid: u32 },
    #[error(transparent)]
    Wire(#[from] dbsec_core::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn main() -> ExitCode {
    // Diagnostics go to stderr, deliberately — `tracing_subscriber::fmt()`
    // would otherwise default to stdout. A long-running proxy's stdout
    // belongs to whatever the operator pipes it into, and `dbsec 2>/dev/null`
    // has to be able to silence the logs without silencing anything else.
    // `tests/cli.rs` pins the choice (TEST-31). Colour follows the same
    // reasoning: escape sequences are for a terminal, not for the journal or
    // log file a redirected stderr usually is.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = match load_config() {
        Ok(config) => config,
        Err(e) => {
            tracing::error!(error = %e, "startup failed");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "failed to start runtime");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(serve(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "proxy exited with error");
            ExitCode::FAILURE
        }
    }
}

/// `dbsec [config.toml]` — a missing default file just means defaults.
fn load_config() -> Result<ValidatedConfig, Error> {
    match std::env::args_os().nth(1) {
        Some(path) => Config::load(Path::new(&path)),
        None => {
            let default = Path::new("dbsec.toml");
            if default.exists() {
                Config::load(default)
            } else {
                Config::default().validated()
            }
        }
    }
}

async fn serve(validated: ValidatedConfig) -> Result<(), Error> {
    let ValidatedConfig { config, protected } = validated;
    let tls = Arc::new(TlsContext::from_config(&config)?);

    // `protected` is `Some` exactly when `[[column]]` entries were configured,
    // and validation already resolved the key source and the control DSN — so
    // there is nothing left to assert here (ERR-11).
    //
    // The column map the read path matches on is resolved here and then kept
    // current by `refresher`: it is keyed by `(table oid, attnum)`, which an
    // ordinary migration invalidates without touching the names the write
    // path uses (see `resolve`).
    let mut refresh = None;
    let (rows, writes) = match &protected {
        None => (None, None),
        Some(protected) => {
            let keys: Arc<dyn dbsec_core::keys::KeySource> = match &protected.keys {
                KeySourceConfig::File(keys_file) => Arc::new(FileKeySource::load(keys_file)?),
                KeySourceConfig::Vault(setup) => {
                    Arc::new(vault::VaultKeySource::connect(setup).await?)
                }
            };
            let columns = Arc::new(columns::build(&config, &keys));
            let dsn = protected.control_dsn.clone();
            let resolved =
                resolve::resolve_columns(&dsn, &tls, &columns, CONNECT_TIMEOUT).await?;
            let rows = Arc::new(RowContext::new(resolved, config.on_unprotected));
            refresh = Some((rows.clone(), dsn, columns.clone()));
            (
                Some(rows),
                Some(Arc::new(encrypt::WriteCatalog::new(&columns, config.on_unprotected))),
            )
        }
    };

    let ctx = Arc::new(SessionContext {
        upstream_addr: config.upstream.clone(),
        tls: tls.clone(),
        rows,
        writes,
        startup_timeout: Duration::from_secs(config.startup_timeout_secs),
    });
    // Named rather than left as a bare `Io`: "Address already in use" without
    // the address is the least useful startup failure there is.
    let listener = TcpListener::bind(&config.listen)
        .await
        .map_err(|source| Error::Listen { addr: config.listen.clone(), source })?;
    tracing::info!(
        listen = %config.listen,
        upstream = %config.upstream,
        downstream_tls = ctx.tls.acceptor.is_some(),
        upstream_tls = ctx.tls.connector.is_some(),
        protected_columns = config.columns.len(),
        max_sessions = config.max_sessions,
        startup_timeout_secs = config.startup_timeout_secs,
        column_refresh_secs = config.column_refresh_secs,
        "dbsec listening"
    );

    // Sessions are a tracked task group rather than detached spawns, so
    // shutdown can wait for them instead of dropping the runtime out from
    // under a half-written frame (CONC-6).
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let refresher = refresh.map(|(rows, dsn, columns)| {
        tokio::spawn(resolve::refresh_loop(
            resolve::Refresher {
                ctx: rows,
                dsn,
                tls,
                columns,
                interval: Duration::from_secs(config.column_refresh_secs),
                deadline: CONNECT_TIMEOUT,
            },
            shutdown_rx.clone(),
        ))
    });
    let mut sessions = JoinSet::new();
    let outcome = tokio::select! {
        result = accept_loop(listener, &ctx, config.max_sessions, &mut sessions, &shutdown_rx) => {
            result
        }
        () = shutdown_signal() => {
            tracing::info!("shutdown requested");
            Ok(())
        }
    };
    let _ = shutdown_tx.send(true);
    if let Some(refresher) = refresher {
        // It only ever waits on a timer or the shutdown signal, so it is
        // already on its way out; the timeout is a backstop for a
        // re-resolution in flight against an unresponsive control connection.
        if tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, refresher).await.is_err() {
            tracing::warn!("column refresher did not stop within the drain timeout");
        }
    }
    drain_sessions(&mut sessions, SHUTDOWN_DRAIN_TIMEOUT).await;
    outcome
}

/// Resolves on SIGINT or, on unix, SIGTERM — the signal a container runtime
/// or systemd sends first, and which the proxy would otherwise never observe.
#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(term) => term,
        Err(e) => {
            tracing::warn!(error = %e, "cannot listen for SIGTERM; SIGINT only");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(e) = result {
                tracing::warn!(error = %e, "SIGINT listener failed");
            }
        }
        _ = term.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::warn!(error = %e, "SIGINT listener failed");
    }
}

/// Waits up to `deadline` for live sessions to finish their current frame,
/// aborts whatever is left, and reports the split. Returns
/// `(drained, aborted)`.
async fn drain_sessions(sessions: &mut JoinSet<()>, deadline: Duration) -> (usize, usize) {
    if sessions.is_empty() {
        tracing::info!("shutdown complete; no live sessions");
        return (0, 0);
    }
    let mut drained = 0usize;
    let _ = tokio::time::timeout(deadline, async {
        while sessions.join_next().await.is_some() {
            drained += 1;
        }
    })
    .await;
    let aborted = sessions.len();
    sessions.shutdown().await;
    tracing::info!(drained, aborted, ?deadline, "shutdown complete");
    (drained, aborted)
}

/// Source of accepted connections. Abstracted over [`TcpListener`] so tests
/// can inject the transient `accept()` failures the kernel produces under
/// descriptor pressure, which are otherwise unreachable from a test.
trait Accept {
    fn accept(&mut self) -> impl Future<Output = std::io::Result<(TcpStream, SocketAddr)>>;
}

impl Accept for TcpListener {
    async fn accept(&mut self) -> std::io::Result<(TcpStream, SocketAddr)> {
        TcpListener::accept(self).await
    }
}

/// Accept errors that invalidate the *listener* rather than the one
/// connection: the descriptor is not a listening socket at all. No amount of
/// retrying fixes those, so they terminate `serve` with a non-zero exit.
///
/// Everything else is transient and per-connection — ECONNABORTED (the peer
/// went away between the SYN and the accept), EMFILE/ENFILE (descriptor
/// exhaustion), ENOBUFS/ENOMEM (kernel buffer pressure), EINTR — and says
/// nothing about the listening socket, which is still bound and still valid.
/// Those shed one connection and the loop continues; killing the process
/// would drop every healthy session with it, and the proxy is the only thing
/// enforcing encryption for the clients behind it (ASYNC-6). None of the
/// exhaustion errnos has a stable `ErrorKind`, so the consecutive-failure
/// ceiling in [`accept_loop`] is what catches a listener failing in a way
/// this predicate cannot name.
fn is_fatal_accept_error(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::InvalidInput | ErrorKind::Unsupported)
}

/// Accept errors that concern only the connection being accepted, so the next
/// `accept()` is worth attempting immediately with no backoff.
fn is_per_connection_accept_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionRefused
            | ErrorKind::Interrupted
    )
}

/// Rate-limited accounting for connections turned away at the session limit:
/// one line per [`REFUSAL_LOG_INTERVAL`] carrying the count, rather than one
/// line per refused connection.
#[derive(Default)]
struct Refusals {
    since_last_log: u64,
    last_log: Option<Instant>,
}

impl Refusals {
    fn record(&mut self, max_sessions: usize) {
        self.since_last_log += 1;
        if self.last_log.is_none_or(|at| at.elapsed() >= REFUSAL_LOG_INTERVAL) {
            tracing::warn!(
                refused = self.since_last_log,
                max_sessions,
                "session limit reached; refusing connections"
            );
            self.last_log = Some(Instant::now());
            self.since_last_log = 0;
        }
    }
}

/// Accepts connections until the listener is genuinely broken, admitting at
/// most `max_sessions` concurrent sessions. Each session's cost is two client
/// sockets plus an upstream backend connection and a relay buffer per
/// direction, none of which the client has authenticated for, so admission is
/// what keeps a connection burst from exhausting descriptors here and
/// `max_connections` on the database behind us (SEC-33).
async fn accept_loop<A: Accept>(
    mut listener: A,
    ctx: &Arc<SessionContext>,
    max_sessions: usize,
    sessions: &mut JoinSet<()>,
    shutdown: &ShutdownRx,
) -> Result<(), Error> {
    let limit = Arc::new(Semaphore::new(max_sessions));
    let mut refusals = Refusals::default();
    let mut consecutive_errors = 0u32;
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            // Reap finished sessions as we go: a `JoinSet` holds every task
            // it has spawned until it is joined, so a long-lived proxy would
            // otherwise accumulate one entry per connection ever served.
            joined = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Err(e)) = joined {
                    tracing::error!(error = %e, "session task terminated abnormally");
                }
                continue;
            }
        };
        let (socket, peer) = match accepted {
            Ok(accepted) => {
                consecutive_errors = 0;
                accepted
            }
            Err(e) if is_fatal_accept_error(&e) => {
                tracing::error!(error = %e, "listener is no longer usable");
                return Err(e.into());
            }
            Err(e) => {
                consecutive_errors += 1;
                if consecutive_errors >= MAX_CONSECUTIVE_ACCEPT_ERRORS {
                    tracing::error!(error = %e, consecutive_errors, "accept kept failing; giving up");
                    return Err(e.into());
                }
                tracing::warn!(error = %e, consecutive_errors, "accept failed; shedding connection");
                if !is_per_connection_accept_error(&e) {
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
                continue;
            }
        };
        // Refusing is deliberate: queueing would only move the exhaustion
        // into this process, and a client that is closed on immediately can
        // retry or fail over, which a client stuck in a queue cannot.
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            refusals.record(max_sessions);
            drop(socket);
            continue;
        };
        let ctx = ctx.clone();
        let shutdown = shutdown.clone();
        sessions.spawn(async move {
            let _permit = permit; // released when the session ends
            tracing::debug!(%peer, "client connected");
            if let Err(e) = session::run(socket, &ctx, shutdown).await {
                tracing::warn!(%peer, error = %e, "session ended with error");
            } else {
                tracing::debug!(%peer, "client disconnected");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// SSLRequest: the cheapest client message the proxy answers on its own,
    /// used here as proof that a connection reached a session task.
    fn ssl_request() -> Vec<u8> {
        let mut msg = 8i32.to_be_bytes().to_vec();
        msg.extend_from_slice(&dbsec_core::pgwire::SSL_REQUEST.to_be_bytes());
        msg
    }

    fn test_ctx() -> Arc<SessionContext> {
        let config = Config::default();
        Arc::new(SessionContext {
            // Never dialled: these tests stop at the SSLRequest answer.
            upstream_addr: "127.0.0.1:1".to_owned(),
            tls: Arc::new(TlsContext::from_config(&config).unwrap()),
            rows: None,
            writes: None,
            startup_timeout: Duration::from_secs(10),
        })
    }

    /// Connects, sends SSLRequest and asserts the `N` answer — which only a
    /// session task that was actually admitted can produce.
    async fn expect_served(addr: SocketAddr) -> TcpStream {
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&ssl_request()).await.unwrap();
        let mut answer = [0u8; 1];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"N");
        client
    }

    /// A listener that fails its first `accept()` the way the kernel does
    /// when the process is out of descriptors, then behaves normally.
    struct FlakyListener {
        inner: TcpListener,
        fail_once: Option<std::io::Error>,
    }

    impl Accept for FlakyListener {
        async fn accept(&mut self) -> std::io::Result<(TcpStream, SocketAddr)> {
            match self.fail_once.take() {
                Some(e) => Err(e),
                None => self.inner.accept().await,
            }
        }
    }

    #[tokio::test]
    async fn accept_loop_refuses_connections_over_the_session_limit() {
        let ctx = test_ctx();
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut sessions = JoinSet::new();

        let clients = async {
            // The one permitted session, held open by a client that stops
            // talking after the SSLRequest.
            let _admitted = expect_served(addr).await;
            // Over the limit: refused without ever reaching a session.
            let mut refused = TcpStream::connect(addr).await.unwrap();
            let mut buf = [0u8; 1];
            assert_eq!(refused.read(&mut buf).await.unwrap(), 0, "expected an immediate close");
        };
        tokio::select! {
            result = accept_loop(listener, &ctx, 1, &mut sessions, &shutdown) => {
                panic!("accept loop ended early: {result:?}");
            }
            () = clients => {}
        }
        assert_eq!(sessions.len(), 1, "only the admitted connection became a session");
    }

    #[tokio::test]
    async fn accept_loop_survives_a_transient_accept_error() {
        let ctx = test_ctx();
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = inner.local_addr().unwrap();
        // EMFILE: the process is out of descriptors. Transient and about this
        // connection only — the listener is still bound.
        let listener =
            FlakyListener { inner, fail_once: Some(std::io::Error::from_raw_os_error(24)) };
        let mut sessions = JoinSet::new();

        let client = async {
            let _served = expect_served(addr).await;
        };
        tokio::select! {
            result = accept_loop(listener, &ctx, 8, &mut sessions, &shutdown) => {
                panic!("accept loop ended on a transient error: {result:?}");
            }
            () = client => {}
        }
        assert_eq!(sessions.len(), 1);
    }

    #[tokio::test]
    async fn accept_loop_gives_up_when_the_listener_is_invalid() {
        struct DeadListener;
        impl Accept for DeadListener {
            async fn accept(&mut self) -> std::io::Result<(TcpStream, SocketAddr)> {
                Err(std::io::Error::from(ErrorKind::InvalidInput))
            }
        }

        let ctx = test_ctx();
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let mut sessions = JoinSet::new();
        let result = accept_loop(DeadListener, &ctx, 8, &mut sessions, &shutdown).await;
        assert!(matches!(result, Err(Error::Io(_))));
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn accept_error_classification_matches_the_documented_split() {
        let emfile = std::io::Error::from_raw_os_error(24);
        assert!(!is_fatal_accept_error(&emfile), "descriptor exhaustion is not fatal");
        assert!(!is_per_connection_accept_error(&emfile), "descriptor exhaustion backs off");

        let aborted = std::io::Error::from(ErrorKind::ConnectionAborted);
        assert!(!is_fatal_accept_error(&aborted));
        assert!(is_per_connection_accept_error(&aborted), "retry immediately");

        assert!(is_fatal_accept_error(&std::io::Error::from(ErrorKind::InvalidInput)));
        assert!(is_fatal_accept_error(&std::io::Error::from(ErrorKind::Unsupported)));
    }

    #[tokio::test]
    async fn drain_sessions_waits_then_aborts_at_the_deadline() {
        let mut sessions = JoinSet::new();
        sessions.spawn(async {});
        sessions.spawn(async { std::future::pending::<()>().await });
        assert_eq!(drain_sessions(&mut sessions, Duration::from_millis(100)).await, (1, 1));
        assert!(sessions.is_empty());

        assert_eq!(drain_sessions(&mut sessions, Duration::from_millis(100)).await, (0, 0));
    }
}
