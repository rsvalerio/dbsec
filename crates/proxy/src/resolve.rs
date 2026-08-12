//! Startup column resolution: one control connection maps every configured
//! `[[column]]` to its `(table oid, attnum)` so the decrypt path can match
//! RowDescription fields. A column that doesn't exist is a startup error —
//! silently protecting nothing would be worse than refusing to start.

use crate::columns::ProtectedColumn;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use dbsec_core::keys::KeySource;

    use crate::config::Config;
    use crate::rows::tests::OneKey;

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
