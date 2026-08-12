//! Startup column resolution: one control connection maps every configured
//! `[[column]]` to its `(table oid, attnum)` so the decrypt path can match
//! RowDescription fields. A column that doesn't exist is a startup error —
//! silently protecting nothing would be worse than refusing to start.

use std::time::Duration;

use tokio::time::timeout;
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres::Socket;

use crate::columns::ProtectedColumn;
use crate::config::Dsn;
use crate::rows::{ColumnMap, ReadColumn};
use crate::tls::TlsContext;
use crate::Error;

const LOOKUP: &str = "\
SELECT a.attrelid, a.attnum
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = $2 AND a.attname = $3
  AND a.attnum > 0 AND NOT a.attisdropped";

/// Resolves every configured column over one control connection. `deadline`
/// bounds each network step separately — the connect and each lookup — so a
/// control endpoint that accepts TCP and then goes silent fails startup
/// instead of hanging the proxy before it ever binds its listener (ASYNC-6).
pub async fn resolve_columns(
    dsn: &Dsn,
    tls: &TlsContext,
    columns: &[ProtectedColumn],
    deadline: Duration,
) -> Result<ColumnMap, Error> {
    let client = connect(dsn, tls, deadline).await?;

    let mut map = ColumnMap::new();
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
        .map_err(|e| Error::Control(e.to_string()))?
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
        if let Some(read) = read_column(column) {
            map.insert((table_oid, attnum), read);
        }
    }
    Ok(map)
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
        .map_err(|e| Error::Control(e.to_string()))?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::warn!(error = %e, "control connection ended with error");
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
            tokio_postgres::config::Host::Tcp(name) => match ports.get(i).or(ports.first()) {
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

        let tls = TlsContext::from_config(&Config::default()).unwrap();
        let dsn = Dsn::new(format!("postgres://dbsec:hunter2@127.0.0.1:{}/app", addr.port()));
        let deadline = Duration::from_millis(200);
        let started = std::time::Instant::now();
        let Err(err) = resolve_columns(&dsn, &tls, &[], deadline).await else {
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
