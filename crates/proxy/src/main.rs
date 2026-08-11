//! dbsec: transparent PostgreSQL proxy for field-level encryption.
//! Frame-aware relay with optional TLS on both hops and transparent
//! decryption of configured columns on the read path. See plans/PLAN.md.

mod columns;
mod config;
mod encrypt;
mod resolve;
mod rows;
mod session;
mod tls;
mod vault;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use dbsec_core::keys::FileKeySource;
use tokio::net::TcpListener;

use crate::config::Config;
use crate::rows::RowContext;
use crate::session::SessionContext;
use crate::tls::TlsContext;

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
    #[error("tls config: {0}")]
    TlsConfig(String),
    #[error("client sent a plaintext startup but TLS is required")]
    PlaintextRejected,
    #[error("upstream {addr} refused TLS")]
    UpstreamTlsRefused { addr: String },
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("vault: {0}")]
    Vault(String),
    #[error("control connection: {0}")]
    Control(String),
    #[error("configured column {table}.{column} does not exist")]
    ColumnNotFound { table: String, column: String },
    #[error(transparent)]
    Wire(#[from] dbsec_core::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
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
fn load_config() -> Result<Config, Error> {
    match std::env::args_os().nth(1) {
        Some(path) => Config::load(Path::new(&path)),
        None => {
            let default = Path::new("dbsec.toml");
            if default.exists() {
                Config::load(default)
            } else {
                Ok(Config::default())
            }
        }
    }
}

async fn serve(config: Config) -> Result<(), Error> {
    let tls = TlsContext::from_config(&config)?;

    let (rows, writes) = if config.columns.is_empty() {
        (None, None)
    } else {
        let keys: Arc<dyn dbsec_core::keys::KeySource> = match (&config.keys_file, &config.vault) {
            (Some(keys_file), None) => Arc::new(FileKeySource::load(keys_file)?),
            (None, Some(vault_config)) => {
                Arc::new(vault::VaultKeySource::connect(vault_config).await?)
            }
            _ => unreachable!("validated: columns require exactly one key source"),
        };
        let protected = columns::build(&config, &keys);
        let dsn = config.control_dsn.as_deref().expect("validated: columns require control_dsn");
        let column_map = resolve::resolve_columns(dsn, &tls, &protected).await?;
        (
            Some(Arc::new(RowContext { columns: column_map })),
            Some(Arc::new(encrypt::WriteCatalog::new(&protected))),
        )
    };

    let ctx =
        Arc::new(SessionContext { upstream_addr: config.upstream.clone(), tls, rows, writes });
    let listener = TcpListener::bind(&config.listen).await?;
    tracing::info!(
        listen = %config.listen,
        upstream = %config.upstream,
        downstream_tls = ctx.tls.acceptor.is_some(),
        upstream_tls = ctx.tls.connector.is_some(),
        protected_columns = config.columns.len(),
        "dbsec listening"
    );

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (socket, peer) = accepted?;
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    tracing::debug!(%peer, "client connected");
                    if let Err(e) = session::run(socket, &ctx).await {
                        tracing::warn!(%peer, error = %e, "session ended with error");
                    } else {
                        tracing::debug!(%peer, "client disconnected");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutdown requested");
                return Ok(());
            }
        }
    }
}
