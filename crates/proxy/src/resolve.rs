//! Startup column resolution: one control connection maps every configured
//! `[[column]]` to its `(table oid, attnum)` so the decrypt path can match
//! RowDescription fields. A column that doesn't exist is a startup error —
//! silently protecting nothing would be worse than refusing to start.

use crate::columns::ProtectedColumn;
use crate::rows::ColumnMap;
use crate::tls::TlsContext;
use crate::Error;

const LOOKUP: &str = "\
SELECT a.attrelid, a.attnum
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = $2 AND a.attname = $3
  AND a.attnum > 0 AND NOT a.attisdropped";

pub async fn resolve_columns(
    dsn: &str,
    tls: &TlsContext,
    columns: &[ProtectedColumn],
) -> Result<ColumnMap, Error> {
    let client = connect(dsn, tls).await?;

    let mut map = ColumnMap::new();
    for column in columns {
        let row = client
            .query_opt(
                LOOKUP,
                &[&column.schema.as_str(), &column.table.as_str(), &column.column.as_str()],
            )
            .await
            .map_err(|e| Error::Control(e.to_string()))?
            .ok_or_else(|| Error::ColumnNotFound {
                table: format!("{}.{}", column.schema, column.table),
                column: column.column.clone(),
            })?;
        let table_oid: u32 = row.get(0);
        let attnum: i16 = row.get(1);
        tracing::info!(
            table = %format!("{}.{}", column.schema, column.table),
            column = %column.column,
            table_oid,
            attnum,
            searchable = column.transform.searchable(),
            "protected column resolved"
        );
        map.insert((table_oid, attnum), column.transform.clone());
    }
    Ok(map)
}

/// Connects with TLS when `[tls.upstream]` is configured (same trust root as
/// the data path), plaintext otherwise.
async fn connect(dsn: &str, tls: &TlsContext) -> Result<tokio_postgres::Client, Error> {
    match &tls.upstream_client {
        Some(client_config) => {
            let connector =
                tokio_postgres_rustls::MakeRustlsConnect::new((**client_config).clone());
            let (client, connection) = tokio_postgres::connect(dsn, connector)
                .await
                .map_err(|e| Error::Control(e.to_string()))?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    tracing::warn!(error = %e, "control connection ended with error");
                }
            });
            Ok(client)
        }
        None => {
            let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
                .await
                .map_err(|e| Error::Control(e.to_string()))?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    tracing::warn!(error = %e, "control connection ended with error");
                }
            });
            Ok(client)
        }
    }
}
