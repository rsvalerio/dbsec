//! dbsec: transparent PostgreSQL proxy for field-level encryption.
//! Frame-aware relay with optional TLS on both hops and transparent
//! decryption of configured columns on the read path. See plans/PLAN.md.

mod columns;
mod config;
mod diag;
mod encrypt;
mod hardening;
mod portal;
mod resolve;
mod rows;
mod session;
mod tls;
mod vault;

use std::ffi::OsString;
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

/// Subscriber filter used when `RUST_LOG` says nothing.
///
/// `vaultrs`/`rustify` log every non-2xx response at ERROR from inside the
/// client, and resolving a deterministic index key for the first time
/// deliberately probes two paths that are *expected* to be absent —
/// `{path}/index_keys/{name}` and the pre-versioning shared map — before
/// minting. A cold start of a working deployment therefore produced a handful
/// of ERROR lines for the proxy doing exactly what it is designed to do,
/// which makes a clean startup look like a failing one and buries the ERROR
/// lines that do matter.
///
/// Those targets are turned off rather than lowered, because the noise is
/// emitted at ERROR itself. Nothing is lost: the proxy attaches its own
/// context at the site that *handles* the failure (`main`'s startup path and
/// [`log_session_error`]), the `vaultrs` error is carried as a `#[source]`
/// rather than formatted away, and those handling sites render the whole chain
/// with [`diag::chain`] — so the library's view of the failure is printed
/// under the proxy's, at the one place it is actionable. An operator who sets
/// `RUST_LOG` owns the filter completely and can put `vaultrs=debug` back in.
///
/// The one security-relevant line `vaultrs` emits — the WARN it logs when it is
/// about to accept invalid certificates — is unreachable from this proxy:
/// `vault::client_settings` pins `verify = true`, so the branch that emits it
/// is never taken. Silencing the target therefore hides nothing that matters;
/// if that pin is ever relaxed, this filter has to be revisited with it.
const DEFAULT_LOG_FILTER: &str = "info,vaultrs=off,rustify=off";

/// Config file loaded when no path is given on the command line.
const DEFAULT_CONFIG: &str = "dbsec.toml";

/// Opt-in for running with no config at all — see [`load_config`].
const PLAIN_RELAY_FLAG: &str = "--plain-relay";

/// Opt-in for leaving core dumps enabled — see [`hardening`].
const ALLOW_CORE_DUMPS_FLAG: &str = "--allow-core-dumps";

/// The two spellings of "tell me what the flags are".
const HELP_FLAGS: [&str; 2] = ["-h", "--help"];

const USAGE: &str = "usage: dbsec [--plain-relay] [--allow-core-dumps] [config.toml]";

/// The rest of `dbsec --help`: what each argument does, and — for the two
/// opt-ins — what it costs, because both of them relax a default that exists
/// to protect data.
const OPTIONS: &str = "\
  config.toml           config to load; with no path, ./dbsec.toml, and a run
                        with neither is refused
  --plain-relay         start with no config at all: no encryption, no TLS and
                        no protected columns
  --allow-core-dumps    leave core dumps enabled; a dump of this process can
                        contain key material
  -h, --help            print this help and exit";

/// What a startup that protects nothing is reported as, whichever way it was
/// reached. A config file with no `[[column]]` entries and
/// [`PLAIN_RELAY_FLAG`] leave the proxy in exactly the same state — every
/// value passes through as the client and the database send it — so they read
/// the same way in the log rather than one being a WARN and the other a field
/// inside the INFO listening line (TASK-0131).
const NO_PROTECTION_WARNING: &str =
    "no protected columns are configured: relaying in plaintext with no encryption and no column \
     protection, so every value passes through exactly as the client and the database send it";

/// Claims the right to install a thread-local `tracing` subscriber and assert
/// on what it saw. Held for as long as the subscriber is.
///
/// `tracing` caches each callsite's interest process-wide and rebuilds that
/// cache only when the number of scoped subscribers rises *from zero*. Every
/// warn-mode test that runs without a subscriber leaves the callsites it
/// touched cached as "never interested"; a capture test starting while another
/// one is still installed does not lift that count from zero, so no rebuild
/// happens and it captures nothing. Serialising them is what keeps the count
/// going 0 → 1 every time.
#[cfg(test)]
pub fn log_capture() -> std::sync::MutexGuard<'static, ()> {
    static LOG_CAPTURE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    dbsec_core::sync::Unpoisoned::unpoisoned(LOG_CAPTURE.lock())
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{message}; {USAGE}")]
    Usage { message: String },
    #[error(
        "no config path was given and {path} does not exist; refusing to start as a plaintext \
         relay with no encryption, no TLS and no protected columns — pass a config path, or \
         {PLAIN_RELAY_FLAG} to run without one deliberately"
    )]
    NoConfig { path: PathBuf },
    #[error("reading config {path}: {source}")]
    ConfigRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Deliberately carries a rendered `reason` rather than the `toml` error
    /// itself: that error's `Display` embeds the offending source line
    /// verbatim, so a lost quote on an inline `[vault] token` or a
    /// `control_dsn` password would print the credential to stderr — the one
    /// leak [`config::Secret`] and [`config::Dsn`] cannot cover, because they
    /// only ever hold values that parsed. [`config::describe_parse_error`]
    /// builds the reason, and the `toml` error is not kept as a `#[source]`
    /// either: anything walking the chain would print the snippet back.
    #[error("parsing config {path}: {reason}")]
    ConfigParse { path: PathBuf, reason: String },
    #[error(
        "{what}: {source}; pass {ALLOW_CORE_DUMPS_FLAG} to start with core dumps left enabled"
    )]
    Hardening {
        what: &'static str,
        #[source]
        source: std::io::Error,
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
    /// The `[vault] token_file` read. Shaped like [`Error::ConfigRead`] rather
    /// than flattened into a string: the file is config-adjacent, so the same
    /// "name the path, keep the `io::Error`" rule applies (ERR-9, ERR-13). The
    /// token itself is never in the error — only the path it was to be read
    /// from.
    #[error("reading the [vault] token_file {path}: {source}")]
    VaultToken {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The control connection is the most failure-prone startup step, and the
    /// part an operator needs — "connection refused" vs "certificate verify
    /// failed" vs "password authentication failed" — lives *under* the
    /// `tokio_postgres` error, not in its top line. So the cause is kept as a
    /// `#[source]` instead of being flattened with `to_string()` (ERR-9), and
    /// the endpoint is named the same way [`Error::ControlTimeout`] names it —
    /// parsed out of the DSN, never echoed, because `control_dsn` carries the
    /// control user's password.
    #[error("control connection to {host}: {source}")]
    Control {
        host: String,
        #[source]
        source: tokio_postgres::Error,
    },
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
    #[error(
        "protected column at result position {position} is {len} bytes, over the {max} byte \
         limit; decrypting it would cost several times that in transient memory"
    )]
    ProtectedValueTooLarge { position: usize, len: usize, max: usize },
    #[error(
        "client sent a {msg_type} frame of {body_len} bytes before the backend authenticated it, \
         over the {max} byte pre-authentication limit"
    )]
    PreAuthFrameTooLarge { msg_type: char, body_len: usize, max: usize },
    #[error(
        "result column {column} is named like a protected column but carries no table identity, \
         so it cannot be decrypted or masked; it is computed or comes from a subquery, and would \
         be returned in its stored form"
    )]
    ComputedProtectedColumn { column: String },
    #[error(
        "the legacy function-call fast path returned a result the proxy cannot attribute to any \
         column, so it cannot be decrypted or masked; use SQL instead of the FunctionCall message"
    )]
    FunctionCallResult,
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
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| DEFAULT_LOG_FILTER.into()),
        )
        .init();

    let config = match start(std::env::args_os().skip(1)) {
        Ok(Startup::Help) => {
            // Help is the one thing this binary writes to stdout, and the one
            // run that never becomes a proxy: there is no stream to keep clean
            // for a pipe because the process exits immediately, and `dbsec
            // --help | grep` and `dbsec --help > flags.txt` are what an
            // operator actually does with it. Diagnostics from a *running*
            // proxy stay on stderr, unchanged — `tests/cli.rs` pins both
            // halves of that split (TEST-31).
            println!("{USAGE}\n\n{OPTIONS}");
            return ExitCode::SUCCESS;
        }
        Ok(Startup::Serve(config)) => config,
        Err(e) => {
            tracing::error!(error = %diag::chain(&e), "startup failed");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %diag::chain(&e), "failed to start runtime");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(serve(*config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %diag::chain(&e), "proxy exited with error");
            ExitCode::FAILURE
        }
    }
}

/// The command line: an optional config path and the two opt-ins that relax a
/// default the proxy is otherwise strict about.
#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    /// Explicit config path. `None` means "discover [`DEFAULT_CONFIG`]".
    config: Option<PathBuf>,
    /// Run with no config at all — see [`load_config`].
    plain_relay: bool,
    /// Leave core dumps enabled — see [`hardening::disable_core_dumps`].
    allow_core_dumps: bool,
    /// Print [`USAGE`] and [`OPTIONS`] and exit successfully, doing nothing
    /// else — see [`Startup::Help`].
    help: bool,
}

/// What [`start`] made of the command line.
///
/// `--help` is not a startup *failure*, so it cannot be an [`Error`]: an
/// operator asking what the flags are must get the flags and a zero exit, not
/// a logged ERROR and a non-zero one that a supervisor would restart on
/// (TASK-0130).
#[derive(Debug)]
enum Startup {
    /// `-h` / `--help`.
    Help,
    /// Boxed because [`ValidatedConfig`] carries the whole config — every
    /// `[[column]]`, the TLS paths and the key source — and an enum is as
    /// large as its largest variant, which would make the unit `Help` arm pay
    /// for all of it.
    Serve(Box<ValidatedConfig>),
}

impl Args {
    /// Parses the arguments after `argv[0]`.
    ///
    /// An unrecognised `-`-prefixed argument is refused rather than taken as a
    /// config path: a mistyped `--plan-relay` would otherwise be reported as a
    /// missing config file, which sends the operator looking for the wrong
    /// problem — and this argument set is exactly the one where getting it
    /// wrong changes what the proxy protects.
    fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, Error> {
        let mut parsed = Self::default();
        for arg in args {
            // A path that is not UTF-8 is `None` here and lands in the config
            // slot below, which is where a path belongs.
            match arg.to_str() {
                Some(PLAIN_RELAY_FLAG) => parsed.plain_relay = true,
                Some(ALLOW_CORE_DUMPS_FLAG) => parsed.allow_core_dumps = true,
                Some(flag) if HELP_FLAGS.contains(&flag) => parsed.help = true,
                Some(unknown) if unknown.starts_with('-') => {
                    return Err(Error::Usage { message: format!("unknown option {unknown}") })
                }
                _ => {
                    if parsed.config.replace(PathBuf::from(&arg)).is_some() {
                        return Err(Error::Usage {
                            message: "more than one config path was given".to_owned(),
                        });
                    }
                }
            }
        }
        Ok(parsed)
    }
}

/// Everything that happens before the runtime exists: the command line, the
/// process hardening that has to be in place before any key material is read,
/// and the config itself.
fn start(args: impl IntoIterator<Item = OsString>) -> Result<Startup, Error> {
    let args = Args::parse(args)?;
    // Answered before the hardening and the config: `--help` must work in a
    // directory with no config, and on a kernel where the core-dump limit
    // cannot be set, or it is not help.
    if args.help {
        return Ok(Startup::Help);
    }
    if !args.allow_core_dumps {
        hardening::disable_core_dumps()?;
    }
    Ok(Startup::Serve(Box::new(load_config(&args, Path::new(DEFAULT_CONFIG))?)))
}

/// `dbsec [config.toml]` — with no path on the command line, `default`, which
/// is [`DEFAULT_CONFIG`] in the working directory for every caller but the
/// tests.
///
/// A missing default file is a refusal, not a fallback to built-in defaults.
/// Those defaults configure no columns and no TLS, so falling back to them
/// turns the proxy into a transparent plaintext relay whose only evidence is
/// `protected_columns=0` in one INFO line — and the ways to get there are
/// mundane: a systemd unit whose `WorkingDirectory` moved, a container whose
/// config volume mounted somewhere else. A deployment that genuinely wants the
/// relay says so with [`PLAIN_RELAY_FLAG`].
///
/// The refusal only covers the *missing* file, though. A config file that
/// exists and declares no `[[column]]` reaches the identical zero-protection
/// state — a `[[column]]` block lost to a bad merge, a templating mistake, an
/// environment overlay — and is the likelier production shape of the two. So
/// the warning is attached to the state rather than to the route taken to it:
/// every startup that protects nothing says so once, at WARN, naming where its
/// config came from (TASK-0131).
fn load_config(args: &Args, default: &Path) -> Result<ValidatedConfig, Error> {
    let (loaded, source) = match &args.config {
        Some(path) => (Config::load(path)?, path.display().to_string()),
        None if default.exists() => (Config::load(default)?, default.display().to_string()),
        None if args.plain_relay => {
            (Config::default().validated()?, format!("none ({PLAIN_RELAY_FLAG})"))
        }
        None => return Err(Error::NoConfig { path: default.to_owned() }),
    };
    // `protected` is `Some` exactly when at least one `[[column]]` was
    // configured, so this is the same condition the read and write paths are
    // switched on — not a second, drifting definition of "protected".
    if loaded.protected.is_none() {
        tracing::warn!(config = %source, "{NO_PROTECTION_WARNING}");
    }
    Ok(loaded)
}

async fn serve(validated: ValidatedConfig) -> Result<(), Error> {
    // Built before the destructure: `TlsContext` only accepts the validated
    // form, which is what proves the downstream key's mode was checked.
    let tls = Arc::new(TlsContext::from_config(&validated)?);
    let ValidatedConfig { config, protected } = validated;

    // `protected` is `Some` exactly when `[[column]]` entries were configured,
    // and validation already resolved the key source and the control DSN — so
    // there is nothing left to assert here (ERR-11).
    //
    // The column map the read path matches on is resolved here and then kept
    // current by `refresher`: it is keyed by `(table oid, attnum)`, which an
    // ordinary migration invalidates without touching the names the write
    // path uses (see `resolve`).
    let mut refresh = None;
    // The Vault key source alone gets a watchdog: its token has a lease that
    // the key caches would otherwise mask until the first cache miss.
    let mut vault_keys = None;
    let (rows, writes) = match &protected {
        None => (None, None),
        Some(protected) => {
            let keys: Arc<dyn dbsec_core::keys::KeySource> = match &protected.keys {
                KeySourceConfig::File(keys_file) => Arc::new(FileKeySource::load(keys_file)?),
                KeySourceConfig::Vault(setup) => {
                    let source = Arc::new(vault::VaultKeySource::connect(setup).await?);
                    vault_keys = Some(source.clone());
                    source
                }
            };
            let columns = Arc::new(columns::build(&config, &keys));
            let dsn = protected.control_dsn.clone();
            let resolved = resolve::resolve_columns(&dsn, &tls, &columns, CONNECT_TIMEOUT).await?;
            let rows = Arc::new(RowContext::new(
                resolved,
                config.on_unprotected,
                config.max_protected_value_bytes,
            ));
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
        max_protected_value_bytes = config.max_protected_value_bytes,
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
    let token_watch =
        vault_keys.map(|keys| tokio::spawn(vault::token_watch(keys, shutdown_rx.clone())));
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
    if let Some(token_watch) = token_watch {
        // Same shape as the refresher: it is either sleeping or mid-lookup,
        // and the timeout backstops a lookup against an unresponsive Vault.
        if tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, token_watch).await.is_err() {
            tracing::warn!("vault token watch did not stop within the drain timeout");
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
                log_session_error(&peer, &e);
            } else {
                tracing::debug!(%peer, "client disconnected");
            }
        });
    }
}

/// Logs a failed session at the level its cause deserves.
///
/// A session that ends because the key backend failed — Vault unreachable, a
/// revoked token, a permission denial — is a fault of the deployment, not of
/// this connection: every session after it fails the same way until an
/// operator acts. That is the case [`DEFAULT_LOG_FILTER`] silences the
/// `vaultrs`/`rustify` targets for, so it is reported here at ERROR instead,
/// with the proxy's own context and — via [`diag::chain`] — the backend error
/// underneath it, which is the half that tells a 403 from a connection
/// refused.
///
/// Everything else stays a WARN: a malformed frame, a rejected rewrite or an
/// envelope written under a DEK this deployment no longer has
/// (`UnknownKey`) is driven by the connection or the stored data, and a
/// client that retries it must not be able to fill the log with ERRORs.
fn log_session_error(peer: &SocketAddr, e: &Error) {
    if is_key_backend_failure(e) {
        tracing::error!(%peer, error = %diag::chain(e), "session ended: the key source is not usable");
    } else {
        tracing::warn!(%peer, error = %diag::chain(e), "session ended with error");
    }
}

fn is_key_backend_failure(e: &Error) -> bool {
    matches!(e, Error::Wire(dbsec_core::Error::KeyBackend { .. } | dbsec_core::Error::KeySource(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn args(argv: &[&str]) -> Result<Args, Error> {
        Args::parse(argv.iter().map(OsString::from))
    }

    #[test]
    fn the_command_line_is_a_config_path_and_two_opt_ins() {
        assert_eq!(args(&[]).unwrap(), Args::default());
        assert_eq!(
            args(&["dbsec.toml"]).unwrap(),
            Args { config: Some(PathBuf::from("dbsec.toml")), ..Args::default() }
        );
        // Order-independent, and a flag is never mistaken for the path.
        assert_eq!(
            args(&[PLAIN_RELAY_FLAG, "a.toml", ALLOW_CORE_DUMPS_FLAG]).unwrap(),
            Args {
                config: Some(PathBuf::from("a.toml")),
                plain_relay: true,
                allow_core_dumps: true,
                ..Args::default()
            }
        );
    }

    /// TASK-0130: asking what the flags are is not a usage *error*. Both
    /// spellings are recognised, and the answer is a `Startup::Help` rather
    /// than an `Error::Usage` — which is what keeps the exit code at 0 and the
    /// text out of a `tracing` ERROR record.
    #[test]
    fn help_is_a_startup_outcome_rather_than_a_usage_error() {
        for flag in HELP_FLAGS {
            assert_eq!(args(&[flag]).unwrap(), Args { help: true, ..Args::default() }, "{flag}");
            assert!(
                matches!(start([OsString::from(flag)]), Ok(Startup::Help)),
                "{flag} must short-circuit startup"
            );
        }
        // Help wins over the rest of the command line: an operator who is
        // asking for the flags does not want the config loaded first.
        assert!(matches!(
            start([OsString::from("/nonexistent/dbsec.toml"), OsString::from("--help")]),
            Ok(Startup::Help)
        ));
        // And the text it prints answers the command line it documents.
        for flag in [PLAIN_RELAY_FLAG, ALLOW_CORE_DUMPS_FLAG].iter().chain(HELP_FLAGS.iter()) {
            assert!(OPTIONS.contains(flag), "{flag} is undocumented");
        }
    }

    /// A mistyped opt-in must not be read as a config path: it would be
    /// reported as a missing file and send the operator after the wrong
    /// problem, on the one argument that decides what the proxy protects.
    #[test]
    fn a_mistyped_option_is_refused_rather_than_taken_for_a_path() {
        let Err(Error::Usage { message }) = args(&["--plan-relay"]) else {
            panic!("an unknown option must be refused");
        };
        assert!(message.contains("--plan-relay"), "{message}");

        assert!(matches!(args(&["a.toml", "b.toml"]), Err(Error::Usage { .. })));
    }

    /// TASK-0088: no argument and no `dbsec.toml` is a refusal, and the
    /// refusal names both the file it looked for and the way to say "yes,
    /// really".
    #[test]
    fn a_missing_config_refuses_to_start_unless_the_plain_relay_opt_in_is_given() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join(DEFAULT_CONFIG);

        let Err(err) = load_config(&Args::default(), &absent) else {
            panic!("a missing config must not fall back to a zero-protection relay");
        };
        let rendered = err.to_string();
        assert!(rendered.contains(DEFAULT_CONFIG), "name the file it looked for: {rendered}");
        assert!(rendered.contains(PLAIN_RELAY_FLAG), "name the opt-in: {rendered}");

        let opted_in = Args { plain_relay: true, ..Args::default() };
        let relay =
            load_config(&opted_in, &absent).expect("the opt-in starts on built-in defaults");
        assert!(relay.protected.is_none(), "a plain relay protects no columns");
        assert_eq!(relay.config.listen, "127.0.0.1:6432");
    }

    /// The opt-in only covers a *missing* file: a discovered config is still
    /// loaded, and still has to be valid.
    #[test]
    fn the_plain_relay_opt_in_never_overrides_a_config_that_is_there() {
        let dir = tempfile::tempdir().unwrap();
        let discovered = dir.path().join(DEFAULT_CONFIG);
        std::fs::write(&discovered, "max_sessions = 0\n").unwrap();

        let opted_in = Args { plain_relay: true, ..Args::default() };
        assert!(matches!(load_config(&opted_in, &discovered), Err(Error::InvalidConfig(_))));
    }

    /// SSLRequest: the cheapest client message the proxy answers on its own,
    /// used here as proof that a connection reached a session task.
    fn ssl_request() -> Vec<u8> {
        let mut msg = 8i32.to_be_bytes().to_vec();
        msg.extend_from_slice(&dbsec_core::pgwire::SSL_REQUEST.to_be_bytes());
        msg
    }

    fn test_ctx() -> Arc<SessionContext> {
        let config = Config::default().validated().unwrap();
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

    /// The expected-absence probes the index-key path makes are logged at
    /// ERROR by the Vault client itself, so a working cold start looked like a
    /// failing one until those targets were quieted.
    #[test]
    fn the_default_filter_quiets_the_vault_client_without_quieting_the_proxy() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let _capture = log_capture();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(DEFAULT_LOG_FILTER));

        tracing::subscriber::with_default(subscriber, || {
            assert!(
                !tracing::event_enabled!(target: "vaultrs::api", tracing::Level::ERROR),
                "an expected 404 probe must not surface as an ERROR line"
            );
            assert!(
                !tracing::event_enabled!(target: "rustify::client", tracing::Level::ERROR),
                "nor must the HTTP layer underneath it"
            );
            assert!(
                tracing::event_enabled!(target: "dbsec::vault", tracing::Level::ERROR),
                "the proxy's own errors stay visible"
            );
            assert!(
                tracing::event_enabled!(target: "dbsec::vault", tracing::Level::INFO),
                "and so does the mint line the probes precede"
            );
        });
    }

    /// The other half of quieting the client: a genuine Vault failure must
    /// still reach the log at ERROR, from the site that handles it.
    #[test]
    fn a_key_backend_failure_is_the_one_session_error_logged_at_error() {
        let revoked = Error::Wire(dbsec_core::Error::KeyBackend {
            context: "reading index key public.users.email".to_owned(),
            source: Box::new(std::io::Error::from(ErrorKind::PermissionDenied)),
        });
        assert!(is_key_backend_failure(&revoked));
        assert!(is_key_backend_failure(&Error::Wire(dbsec_core::Error::KeySource(
            "resolving index key: vault did not answer within 5s".to_owned()
        ))));

        assert!(
            !is_key_backend_failure(&Error::Wire(dbsec_core::Error::UnknownKey("ab".to_owned()))),
            "stored data written under a lost DEK is not an operator-actionable backend fault"
        );
        assert!(!is_key_backend_failure(&Error::UndescribedRow));
        assert!(!is_key_backend_failure(&Error::Io(std::io::Error::from(ErrorKind::BrokenPipe))));
    }

    /// TASK-0138: `KeyBackend`'s `Display` is `key source: {context}` and says
    /// nothing about *why* the backend refused. The cause it keeps as a
    /// `#[source]` is the half that separates a revoked token from an
    /// unreachable Vault, and it is also the half `DEFAULT_LOG_FILTER`
    /// silences at the `vaultrs` target — so the handling site has to render
    /// it, or the process never prints it at all.
    #[test]
    fn a_key_backend_failure_reports_the_cause_the_vault_target_is_silenced_for() {
        let revoked = Error::Wire(dbsec_core::Error::KeyBackend {
            context: "reading index key public.users.email".to_owned(),
            source: Box::new(std::io::Error::from(ErrorKind::PermissionDenied)),
        });
        let top = revoked.to_string();
        assert!(!top.contains("permission denied"), "precondition: Display drops it: {top}");

        let rendered = diag::chain(&revoked).to_string();
        assert!(rendered.starts_with(&top), "the proxy's own context stays first: {rendered}");
        assert!(rendered.contains("permission denied"), "{rendered}");
    }

    /// TASK-0138 AC3, and the one thing a chain renderer must not do here:
    /// [`Error::ConfigParse`] deliberately holds a rendered `reason` and no
    /// `#[source]`, because the `toml` error's own `Display` quotes the
    /// offending line back — which on a malformed `control_dsn` or inline
    /// `[vault] token` is the credential itself. Walking `source()` must not
    /// become the way back to it.
    #[test]
    fn rendering_a_config_parse_failure_cannot_reach_the_line_it_choked_on() {
        let dir = tempfile::tempdir().unwrap();
        let broken = dir.path().join("broken.toml");
        // A lost opening quote: the value runs to the end of the line, and the
        // line is a DSN carrying the control user's password.
        std::fs::write(&broken, "control_dsn = postgres://control:hunter2@db:5432/app\"\n")
            .unwrap();

        let Err(e) = Config::load(&broken) else { panic!("the file must not parse") };
        assert!(matches!(e, Error::ConfigParse { .. }), "expected a parse failure, got: {e}");
        assert!(std::error::Error::source(&e).is_none(), "ConfigParse must keep no source");

        let rendered = diag::chain(&e).to_string();
        assert!(!rendered.contains("hunter2"), "the credential must not reach the log: {rendered}");
        assert_eq!(rendered, e.to_string(), "there is nothing under it to render");
    }
}
