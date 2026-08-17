//! Protected-column specs shared by both data paths: the write path matches
//! them by name against SQL, the read path by `(table oid, attnum)` after
//! startup resolution. Both paths share one `FieldTransform` per column.

use std::sync::Arc;

use dbsec_core::envelope::{CellContext, Ciphers};
use dbsec_core::keys::KeySource;
use dbsec_core::mask::MaskSpec;
use dbsec_core::transform::{EncryptTransform, FieldTransform, FpeTransform, TokenTransform};

use crate::config::{Config, TransformKind};

pub struct ProtectedColumn {
    pub schema: String,
    pub table: String,
    pub column: String,
    /// `None` for mask-only columns — writes pass through untouched.
    pub transform: Option<Arc<dyn FieldTransform>>,
    pub searchable: bool,
    /// Whether the read path should try to open stored values. False for
    /// irreversible tokens and FPE with detokenize disabled.
    pub readable: bool,
    /// Read-path mask, applied after opening (or to the raw value when
    /// nothing opens).
    pub mask: Option<MaskSpec>,
}

impl ProtectedColumn {
    pub fn qualified_name(&self) -> String {
        format!("{}.{}.{}", self.schema, self.table, self.column)
    }
}

/// Builds one spec per `[[column]]`. Deterministic keys (blind index, FPE,
/// token HMAC) are named `schema.table.column` — the keyfile's `[index_keys]`
/// table (or the KMS) must carry that name.
pub fn build(config: &Config, keys: &Arc<dyn KeySource>) -> Vec<ProtectedColumn> {
    // One DEK cipher cache for the whole process: every encrypted column shares
    // the active key's schedule and, more importantly, its single AES-GCM
    // invocation budget (a per-column budget would let N columns spend N times
    // the random-nonce limit).
    let ciphers = Arc::new(Ciphers::new(keys.clone()));
    config
        .columns
        .iter()
        .map(|column| {
            let (schema, table) = column.schema_and_table();
            let key_name = format!("{schema}.{table}.{}", column.column);
            let (transform, readable): (Option<Arc<dyn FieldTransform>>, bool) = match column
                .transform
            {
                TransformKind::Encrypt => {
                    let index_key = column.searchable.then(|| key_name.clone());
                    // The same `schema.table.column` that names the index key
                    // is bound into every envelope this column writes, so a
                    // ciphertext moved to another column stops authenticating.
                    // Both data paths reach this one transform for the column,
                    // so write and read always agree on the binding.
                    let context = CellContext::new(key_name);
                    (
                        Some(Arc::new(EncryptTransform::new(ciphers.clone(), context, index_key))),
                        true,
                    )
                }
                TransformKind::Fpe => (
                    Some(Arc::new(FpeTransform::new(keys.clone(), key_name, column.detokenize))),
                    column.detokenize,
                ),
                TransformKind::Token => {
                    (Some(Arc::new(TokenTransform::new(keys.clone(), key_name))), false)
                }
                TransformKind::None => (None, false),
            };
            ProtectedColumn {
                schema: schema.to_owned(),
                table: table.to_owned(),
                column: column.column.clone(),
                transform,
                searchable: column.searchable,
                readable,
                mask: column.mask,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rows::tests::OneKey;
    use dbsec_core::transform::WireForm;

    #[test]
    fn build_maps_kinds_to_transforms_and_readability() {
        let config: Config = toml::from_str(
            "keys_file = \"k\"\ncontrol_dsn = \"d\"\n\
             \n[[column]]\ntable = \"users\"\ncolumn = \"email\"\nsearchable = true\n\
             \n[[column]]\ntable = \"cards\"\ncolumn = \"pan\"\ntransform = \"fpe\"\nmask = { keep_last = 4 }\n\
             \n[[column]]\ntable = \"cards\"\ncolumn = \"pin\"\ntransform = \"fpe\"\ndetokenize = false\n\
             \n[[column]]\ntable = \"users\"\ncolumn = \"ssn\"\ntransform = \"token\"\n\
             \n[[column]]\ntable = \"users\"\ncolumn = \"notes\"\ntransform = \"none\"\nmask = { keep_first = 1 }\n",
        )
        .unwrap();
        let keys: Arc<dyn KeySource> = Arc::new(OneKey);
        let columns = build(&config, &keys);

        assert_eq!(columns.len(), 5);
        assert_eq!(columns[0].qualified_name(), "public.users.email");
        assert!(columns[0].readable && columns[0].searchable);
        assert_eq!(columns[0].transform.as_ref().unwrap().wire(), WireForm::Bytea);
        assert!(columns[0].mask.is_none());

        assert!(columns[1].readable);
        assert_eq!(columns[1].transform.as_ref().unwrap().wire(), WireForm::Text);
        assert_eq!(columns[1].mask.unwrap().keep_last, 4);

        assert!(!columns[2].readable, "fpe with detokenize=false is write-only");
        assert!(!columns[3].readable, "tokens are irreversible");

        assert!(columns[4].transform.is_none(), "mask-only column has no transform");
        assert_eq!(columns[4].mask.unwrap().keep_first, 1);
    }

    /// Two encrypted columns share one DEK, so only the per-column binding
    /// stops stored bytes being moved from one into the other. This pins the
    /// wiring: the transform each column gets is bound to *its* name.
    #[test]
    fn each_encrypted_column_is_bound_to_its_own_name() {
        let config: Config = toml::from_str(
            "keys_file = \"k\"\ncontrol_dsn = \"d\"\n\
             \n[[column]]\ntable = \"users\"\ncolumn = \"ssn\"\n\
             \n[[column]]\ntable = \"users\"\ncolumn = \"credit_card\"\n",
        )
        .unwrap();
        let keys: Arc<dyn KeySource> = Arc::new(OneKey);
        let columns = build(&config, &keys);

        let ssn = columns[0].transform.as_ref().expect("encrypt column has a transform");
        let card = columns[1].transform.as_ref().expect("encrypt column has a transform");

        let stored = ssn.seal(b"078-05-1120").unwrap();
        assert!(
            matches!(card.open(&stored), Err(dbsec_core::Error::Decrypt)),
            "an ssn value pasted into credit_card must not authenticate"
        );
        assert_eq!(ssn.open(&stored).unwrap().unwrap(), b"078-05-1120");
    }
}
