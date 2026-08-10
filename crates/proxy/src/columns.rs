//! Protected-column specs shared by both data paths: the write path matches
//! them by name against SQL, the read path by `(table oid, attnum)` after
//! startup resolution. Both paths share one `EncryptTransform` per column.

use std::sync::Arc;

use dbsec_core::keys::KeySource;
use dbsec_core::transform::EncryptTransform;

use crate::config::Config;

pub struct ProtectedColumn {
    pub schema: String,
    pub table: String,
    pub column: String,
    pub transform: Arc<EncryptTransform>,
}

/// Builds one spec per `[[column]]`. Searchable columns get a blind index
/// under a key named `schema.table.column` — the keyfile's `[index_keys]`
/// table (or the KMS) must carry that name.
pub fn build(config: &Config, keys: &Arc<dyn KeySource>) -> Vec<ProtectedColumn> {
    config
        .columns
        .iter()
        .map(|column| {
            let (schema, table) = column.schema_and_table();
            let index_key =
                column.searchable.then(|| format!("{schema}.{table}.{}", column.column));
            ProtectedColumn {
                schema: schema.to_owned(),
                table: table.to_owned(),
                column: column.column.clone(),
                transform: Arc::new(EncryptTransform::new(keys.clone(), index_key)),
            }
        })
        .collect()
}
