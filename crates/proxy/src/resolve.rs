//! Column resolution: one control connection maps every configured
//! `[[column]]` to its `(table oid, attnum)` so the decrypt path can match
//! RowDescription fields. A column that doesn't exist is a startup error —
//! silently protecting nothing would be worse than refusing to start.
//!
//! That mapping is **not** valid for the life of the process. The read path
//! keys on `(table_oid, attnum)` while the write path keys on the column's
//! *name*, and an ordinary migration moves the first without touching the
//! second: `DROP TABLE t; CREATE TABLE t (...)` gives a new `pg_class.oid`,
//! and `ALTER TABLE t DROP COLUMN c, ADD COLUMN c ...` gives a new `attnum`
//! (PostgreSQL never reuses one). A proxy that trusted its startup snapshot
//! would keep encrypting every write and stop decrypting every read, with no
//! error on either side — the client receives `blind_index || envelope` bytes
//! and stores or displays them as the value (CL-3).
//!
//! So [`refresh_loop`] re-resolves on a timer, and a session that sees a
//! result column named like a configured one but absent from the current
//! mapping wakes it immediately ([`crate::rows::RowDecryptor`]). Re-resolution
//! is deliberately *not* fatal: the proxy is already serving traffic, and a
//! control connection that fails at minute ten is a reason to warn and keep
//! the last good mapping, not to drop every live session.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres::Socket;

use crate::columns::ProtectedColumn;
use crate::columns::RowKeyDecl;
use crate::config::Dsn;
use crate::rows::{ColumnMap, ReadColumn, Resolved, ResolvedRowKey, RowContext};
use crate::tls::TlsContext;
use crate::Error;

const LOOKUP: &str = "\
SELECT a.attrelid, a.attnum, a.atttypid
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = $2 AND a.attname = $3
  AND a.attnum > 0 AND NOT a.attisdropped";

/// Everything [`refresh_loop`] needs to redo what `serve` did once at startup.
pub struct Refresher {
    pub ctx: Arc<RowContext>,
    pub dsn: Dsn,
    pub tls: Arc<TlsContext>,
    pub columns: Arc<Vec<ProtectedColumn>>,
    /// The declared row keys, resolved alongside the columns so a migration
    /// that moves the key column is picked up by the same refresh.
    pub row_keys: Arc<Vec<RowKeyDecl>>,
    /// Zero disables the timer, leaving only the on-demand path.
    pub interval: Duration,
    /// The same per-step network deadline startup resolution uses.
    pub deadline: Duration,
}

/// Re-resolves the column map on a timer, and immediately whenever a session
/// reports a RowDescription its mapping could not explain. A failed
/// re-resolution keeps the previous mapping: it is strictly better than the
/// alternative, which is a proxy that stops decrypting because its control
/// connection blipped.
///
/// Returns when `shutdown` fires. `interval` of zero disables the timer, which
/// leaves only the on-demand path.
pub async fn refresh_loop(refresher: Refresher, mut shutdown: crate::session::ShutdownRx) {
    let Refresher { ctx, dsn, tls, columns, row_keys, interval, deadline } = refresher;
    loop {
        let tick = async {
            if interval.is_zero() {
                std::future::pending::<()>().await;
            } else {
                tokio::time::sleep(interval).await;
            }
        };
        tokio::select! {
            () = tick => {}
            () = ctx.refresh_requested() => {}
            _ = shutdown.changed() => return,
        }
        match resolve_columns(&dsn, &tls, &columns, &row_keys, deadline).await {
            Ok(resolved) => {
                report_drift(&ctx.resolved(), &resolved);
                ctx.publish(resolved);
            }
            // Including a column that no longer exists: mid-migration the
            // table may be gone for a moment, and refusing to serve because
            // of it would turn a schema change into an outage.
            Err(e) => tracing::warn!(error = %crate::diag::chain(&e), "could not re-resolve \
                 protected columns; keeping the previous mapping"),
        }
    }
}

/// Logs every protected position that moved between two resolutions. This is
/// the actionable line: between the migration and this message the read path
/// was relaying stored values for that column while the write path kept
/// sealing them.
fn report_drift(previous: &Resolved, current: &Resolved) {
    for (column, was) in &previous.positions {
        let Some(now) = current.positions.get(column) else { continue };
        if now == was {
            continue;
        }
        tracing::warn!(
            column,
            previous_table_oid = was.0,
            previous_attnum = was.1,
            table_oid = now.0,
            attnum = now.1,
            "a protected column moved: the table or column was recreated since it was resolved. \
             Writes kept being encrypted; reads between the migration and now relayed stored \
             values to clients. Re-check any row read in that window."
        );
    }
}

/// Resolves every configured column over one control connection. `deadline`
/// bounds each network step separately — the connect and each lookup — so a
/// control endpoint that accepts TCP and then goes silent fails startup
/// instead of hanging the proxy before it ever binds its listener (ASYNC-6).
pub async fn resolve_columns(
    dsn: &Dsn,
    tls: &TlsContext,
    columns: &[ProtectedColumn],
    row_keys: &[RowKeyDecl],
    deadline: Duration,
) -> Result<Resolved, Error> {
    let client = connect(dsn, tls, deadline).await?;

    let mut map = ColumnMap::new();
    let mut names = std::collections::HashSet::new();
    let mut positions = std::collections::HashMap::new();
    for column in columns {
        let row = timeout(
            deadline,
            client.query_opt(
                LOOKUP,
                &[&column.schema.as_str(), &column.table.as_str(), &column.column.as_str()],
            ),
        )
        .await
        .map_err(|_| Error::ControlTimeout { host: control_host(dsn.as_str()), timeout: deadline })?
        .map_err(|source| Error::Control { host: control_host(dsn.as_str()), source })?
        .ok_or_else(|| Error::ColumnNotFound {
            table: format!("{}.{}", column.schema, column.table),
            column: column.column.clone(),
        })?;
        let table_oid: u32 = row.get(0);
        let attnum: i16 = row.get(1);
        tracing::info!(
            column = %column.qualified_name(),
            table_oid,
            attnum,
            searchable = column.searchable,
            readable = column.readable,
            "protected column resolved"
        );
        positions.insert(column.qualified_name(), (table_oid, attnum));
        if let Some(read) = read_column(column) {
            // Only columns the read path actually rewrites go into `names`:
            // a write-only column (an irreversible token, FPE without
            // detokenize) is *meant* to reach the client in its stored form,
            // so seeing one unmapped is not evidence of anything.
            names.insert(column.column.to_lowercase());
            map.insert((table_oid, attnum), read);
        }
    }
    let mut resolved_row_keys = std::collections::HashMap::new();
    let mut row_keys_by_table = std::collections::HashMap::new();
    for decl in row_keys {
        let row = timeout(
            deadline,
            client.query_opt(
                LOOKUP,
                &[&decl.schema.as_str(), &decl.table.as_str(), &decl.column.as_str()],
            ),
        )
        .await
        .map_err(|_| Error::ControlTimeout { host: control_host(dsn.as_str()), timeout: deadline })?
        .map_err(|source| Error::Control { host: control_host(dsn.as_str()), source })?
        .ok_or_else(|| Error::ColumnNotFound {
            table: format!("{}.{}", decl.schema, decl.table),
            column: decl.column.clone(),
        })?;
        let table_oid: u32 = row.get(0);
        let attnum: i16 = row.get(1);
        let type_oid: u32 = row.get(2);
        // Refused here rather than per row on the data path: the operator
        // learns at startup that this column cannot be a row key, instead of
        // every protected read failing later with the same reason.
        if !crate::rowkey::supported(type_oid) {
            return Err(Error::RowKeyType(format!(
                "{}.{}.{} has type oid {type_oid}, which cannot be canonicalised as a row key; \
                 use an integer, text or uuid column",
                decl.schema, decl.table, decl.column
            )));
        }
        tracing::info!(
            row_key = %format!("{}.{}.{}", decl.schema, decl.table, decl.column),
            table_oid,
            attnum,
            type_oid,
            "row key resolved; this table's encrypted values are bound to their row"
        );
        let spec = ResolvedRowKey { attnum, type_oid, name: decl.column.clone() };
        row_keys_by_table
            .insert((decl.schema.to_lowercase(), decl.table.to_lowercase()), spec.clone());
        resolved_row_keys.insert(table_oid, spec);
    }

    // `generation` is stamped by `RowContext::publish`, which is the only
    // thing that knows which resolution this becomes.
    Ok(Resolved {
        columns: map,
        names,
        positions,
        row_keys: resolved_row_keys,
        row_key_by_table: row_keys_by_table,
        ..Resolved::default()
    })
}

/// What the read path should do with a resolved column, or `None` when it
/// should not touch it at all. Only openable transforms and masks join the
/// map: write-only columns (tokens, FPE without detokenize) relay untouched
/// unless they are masked, and a mask-only column has nothing to open.
fn read_column(column: &ProtectedColumn) -> Option<ReadColumn> {
    if !column.readable && column.mask.is_none() {
        return None;
    }
    let transform = column.readable.then(|| column.transform.clone()).flatten();
    Some(ReadColumn { transform, mask: column.mask })
}

/// Connects with TLS when `[tls.upstream]` is configured (same trust root as
/// the data path), plaintext otherwise. Both hops share one body: only the
/// connector differs (DUP-4).
async fn connect(
    dsn: &Dsn,
    tls: &TlsContext,
    deadline: Duration,
) -> Result<tokio_postgres::Client, Error> {
    match &tls.upstream_client {
        Some(client_config) => {
            let connector =
                tokio_postgres_rustls::MakeRustlsConnect::new((**client_config).clone());
            connect_with(dsn, connector, deadline).await
        }
        None => connect_with(dsn, tokio_postgres::NoTls, deadline).await,
    }
}

/// Connects with `connector` under `deadline` and spawns the connection task
/// that drives the resulting client.
async fn connect_with<T>(
    dsn: &Dsn,
    connector: T,
    deadline: Duration,
) -> Result<tokio_postgres::Client, Error>
where
    T: MakeTlsConnect<Socket>,
    T::Stream: Send + 'static,
    T::TlsConnect: Send,
    <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    let (client, connection) = timeout(deadline, tokio_postgres::connect(dsn.as_str(), connector))
        .await
        .map_err(|_| Error::ControlTimeout { host: control_host(dsn.as_str()), timeout: deadline })?
        .map_err(|source| Error::Control { host: control_host(dsn.as_str()), source })?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::warn!(error = %crate::diag::chain(&e), "control connection ended with error");
        }
    });
    Ok(client)
}

/// The endpoint(s) `dsn` points at, for diagnostics. Parsed out rather than
/// echoed: `control_dsn` carries the control user's password, and an error
/// message is the one place it must not surface.
fn control_host(dsn: &str) -> String {
    let Ok(config) = dsn.parse::<tokio_postgres::Config>() else {
        return "<unparseable control_dsn>".to_owned();
    };
    let ports = config.get_ports();
    let hosts: Vec<String> = config
        .get_hosts()
        .iter()
        .enumerate()
        .map(|(i, host)| match host {
            tokio_postgres::config::Host::Tcp(name) => match ports.get(i).or_else(|| ports.first())
            {
                Some(port) => format!("{name}:{port}"),
                None => name.clone(),
            },
            tokio_postgres::config::Host::Unix(path) => path.display().to_string(),
        })
        .collect();
    if hosts.is_empty() {
        return "<no host in control_dsn>".to_owned();
    }
    hosts.join(",")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dbsec_core::keys::KeySource;

    use super::*;
    use crate::config::Config;
    use crate::rows::tests::OneKey;

    #[test]
    fn control_host_names_the_endpoint_without_the_password() {
        assert_eq!(
            control_host("postgres://dbsec:hunter2@db.internal:5433/app"),
            "db.internal:5433"
        );
        assert_eq!(control_host("host=/var/run/postgresql dbname=app"), "/var/run/postgresql");
        assert!(control_host("this is not a dsn").starts_with('<'));
    }

    /// A control endpoint that completes the TCP connect and then says
    /// nothing is the case a bare `tokio_postgres::connect` waits out
    /// forever, before the proxy has bound its listener.
    #[tokio::test]
    async fn a_silent_control_endpoint_fails_within_the_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepting = tokio::spawn(async move {
            // Accepted sockets are held, not answered: dropping them would
            // close the connection and turn this into a connect *error*.
            let mut accepted = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                accepted.push(socket);
            }
        });

        let tls = TlsContext::from_config(&Config::default().validated().unwrap()).unwrap();
        let dsn = Dsn::new(format!("postgres://dbsec:hunter2@127.0.0.1:{}/app", addr.port()));
        let deadline = Duration::from_millis(200);
        let started = std::time::Instant::now();
        let Err(err) = resolve_columns(&dsn, &tls, &[], &[], deadline).await else {
            panic!("a control endpoint that never answers must not resolve");
        };

        assert!(
            matches!(&err, Error::ControlTimeout { host, timeout }
                if host.contains(&addr.port().to_string()) && *timeout == deadline),
            "expected a control timeout naming the endpoint, got: {err}"
        );
        assert!(!err.to_string().contains("hunter2"), "the DSN password must not reach the error");
        assert!(started.elapsed() < Duration::from_secs(5), "the deadline did not fire");
        accepting.abort();
    }

    /// The same trust configuration the control hop gets from
    /// `[tls.upstream]`, minus the roots: the endpoint under test never
    /// presents a certificate, so an empty store cannot be what fails the
    /// connection.
    fn upstream_tls() -> TlsContext {
        crate::tls::install_crypto_provider().expect("the crypto provider installs");
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        TlsContext { acceptor: None, connector: None, upstream_client: Some(Arc::new(client)) }
    }

    /// An endpoint answering `N` to the SSLRequest is either a server with no
    /// TLS or a MITM stripping the offer. `tokio_postgres` would take that as
    /// permission to continue in plaintext under its default `sslmode=prefer`
    /// — which is why `Config::validate` refuses a `control_dsn` weaker than
    /// `require` once `[tls.upstream]` is set. This is the other half of that
    /// check: with `require`, the strip attempt ends the connection instead of
    /// downgrading it.
    #[tokio::test]
    async fn a_control_endpoint_that_strips_tls_gets_no_plaintext_session() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stripping = tokio::spawn(async move {
            // Sockets are held rather than dropped, so a client that decides
            // to carry on in plaintext gets a live connection to carry on
            // over — the downgrade has to fail on its own merits.
            let mut held = Vec::new();
            while let Ok((mut socket, _)) = listener.accept().await {
                // SSLRequest is a fixed 8-byte message; `N` is "no TLS here".
                let mut request = [0_u8; 8];
                if socket.read_exact(&mut request).await.is_ok() {
                    let _ = socket.write_all(b"N").await;
                }
                held.push(socket);
            }
        });

        let dsn = Dsn::new(format!(
            "postgres://dbsec:hunter2@127.0.0.1:{}/app?sslmode=require",
            addr.port()
        ));
        let deadline = Duration::from_secs(5);
        let started = std::time::Instant::now();
        let Err(err) = connect(&dsn, &upstream_tls(), deadline).await else {
            panic!("a stripped TLS offer must not produce a control connection");
        };

        assert!(
            matches!(err, Error::Control { .. }),
            "the strip must fail the connect, not time out: {err}"
        );
        assert!(!err.to_string().contains("hunter2"), "the DSN password must not reach the error");
        assert!(started.elapsed() < deadline, "the refusal is immediate, not a timeout");
        stripping.abort();
    }

    /// ERR-9: the `tokio_postgres` error is kept as a `#[source]` rather than
    /// flattened with `to_string()`. Its top line is the same for every
    /// connect failure — "error connecting to server" — so the part that tells
    /// "connection refused" apart from "certificate verify failed" apart from
    /// "password authentication failed" is only reachable one link further
    /// down the chain.
    ///
    /// A Unix socket that does not exist rather than a closed TCP port: the
    /// failure is then a deterministic `ENOENT` instead of a race with
    /// whatever else may bind an ephemeral port.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_control_connection_keeps_its_typed_cause() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nothing-listens-here");

        let tls = TlsContext::from_config(&Config::default().validated().unwrap()).unwrap();
        let dsn =
            Dsn::new(format!("host={} user=dbsec password=hunter2 dbname=app", socket.display()));
        let Err(err) = resolve_columns(&dsn, &tls, &[], &[], Duration::from_secs(5)).await else {
            panic!("a control socket that does not exist must not resolve");
        };

        let Error::Control { host, .. } = &err else {
            panic!("expected a control-connection error, got: {err}");
        };
        assert_eq!(host, &socket.display().to_string());
        assert!(!err.to_string().contains("hunter2"), "the DSN password must not reach the error");

        // The chain, not the top line, is where the cause lives.
        let cause =
            std::error::Error::source(&err).expect("the tokio_postgres cause stays reachable");
        let io = cause.source().expect("and its own io::Error under that");
        assert!(io.to_string().contains("No such file or directory"), "{io}");

        // TASK-0138: keeping the cause is only half of it — the startup path
        // logs this error, and what it logs has to include the `io::Error`.
        // "control connection to …: error connecting to server" on its own is
        // the same line for a refused connection, a missing socket and a
        // failed certificate check.
        let logged = crate::diag::chain(&err).to_string();
        assert!(logged.contains("No such file or directory"), "{logged}");
        assert!(logged.starts_with(&err.to_string()), "the proxy's context stays first: {logged}");
        assert!(!logged.contains("hunter2"), "and the password still stays out: {logged}");
    }

    /// One `[[column]]` per read-path shape the filter has to tell apart.
    fn protected() -> Vec<ProtectedColumn> {
        let config: Config = toml::from_str(
            "keys_file = \"k\"\ncontrol_dsn = \"d\"\n\
             \n[[column]]\ntable = \"users\"\ncolumn = \"email\"\nsearchable = true\n\
             \n[[column]]\ntable = \"cards\"\ncolumn = \"pan\"\ntransform = \"fpe\"\nmask = { keep_last = 4 }\n\
             \n[[column]]\ntable = \"cards\"\ncolumn = \"pin\"\ntransform = \"fpe\"\ndetokenize = false\n\
             \n[[column]]\ntable = \"users\"\ncolumn = \"ssn\"\ntransform = \"token\"\nmask = { keep_last = 4 }\n\
             \n[[column]]\ntable = \"users\"\ncolumn = \"notes\"\ntransform = \"none\"\nmask = { keep_first = 1 }\n",
        )
        .expect("test config parses");
        let keys: Arc<dyn KeySource> = Arc::new(OneKey);
        crate::columns::build(&config, &keys)
    }

    #[test]
    fn readable_column_joins_the_read_path_with_its_transform() {
        let columns = protected();

        let email = read_column(&columns[0]).expect("readable columns are decrypted");
        assert!(email.transform.is_some());
        assert!(email.mask.is_none());

        let pan = read_column(&columns[1]).expect("detokenized fpe is opened");
        assert!(pan.transform.is_some());
        assert_eq!(pan.mask.expect("masked").keep_last, 4);
    }

    #[test]
    fn column_that_is_neither_readable_nor_masked_stays_out_of_the_read_path() {
        let columns = protected();

        assert!(
            read_column(&columns[2]).is_none(),
            "fpe with detokenize = false is write-only and must relay untouched"
        );
    }

    #[test]
    fn unreadable_but_masked_column_joins_the_read_path_without_a_transform() {
        let columns = protected();

        let ssn = read_column(&columns[3]).expect("a masked token is still rewritten");
        assert!(ssn.transform.is_none(), "tokens are irreversible; nothing to open");
        assert_eq!(ssn.mask.expect("masked").keep_last, 4);
    }

    #[test]
    fn mask_only_column_joins_the_read_path_with_only_its_mask() {
        let columns = protected();

        let notes = read_column(&columns[4]).expect("mask-only columns are masked on read");
        assert!(notes.transform.is_none());
        assert_eq!(notes.mask.expect("masked").keep_first, 1);
    }
}
