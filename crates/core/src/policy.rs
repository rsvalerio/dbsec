//! The column policy: which columns are protected, how, and which tables bind
//! their values to a row. Shared by every front end — the `dbsec` proxy
//! deserializes its `[[column]]` / `[[table]]` tables straight into these
//! types, and an application linking the library builds them in code — so
//! that both reach one [`Policy::build`] and one set of refusals.
//!
//! # The `schema.table.column` convention
//!
//! A protected column is named `schema.table.column`, with the schema
//! defaulting to `public` when a table name carries no dot. That string is
//! *both*:
//!
//! - the name under which the column's deterministic key (blind index, FPE,
//!   HMAC token) is looked up in the [`KeySource`], and
//! - for `encrypt` columns, the [`CellContext`] bound into every envelope's
//!   associated data, so a ciphertext moved to another column stops
//!   authenticating.
//!
//! The two are the same string on purpose, and [`Policy::build`] is the only
//! place it is formed. An embedder that assembled transforms by hand and named
//! them differently would lose cross-column relocation protection with no
//! error at write time or read time — a value would still open under its own
//! column — which is why the builder lives here rather than in any front end.
//!
//! # Validation
//!
//! [`Policy::validate`] refuses the configurations that would *look* like
//! protection while providing none: a `searchable` non-`encrypt` column, a
//! `row_key` on a table with no encrypted column to bind, a `transform =
//! "none"` column with no mask. The proxy and a library caller get the same
//! refusals because they run the same function.

use std::collections::HashSet;
use std::sync::Arc;

use serde::Deserialize;

use crate::envelope::{CellContext, Ciphers};
use crate::ident::{fold_identifier, MAX_IDENTIFIER_BYTES};
use crate::keys::KeySource;
use crate::mask::MaskSpec;
use crate::transform::{EncryptTransform, FieldTransform, FpeTransform, TokenTransform};
use crate::Error;

/// Schema a bare table name resolves to.
pub const DEFAULT_SCHEMA: &str = "public";

/// Splits `schema.table`, defaulting the schema to [`DEFAULT_SCHEMA`].
pub fn split_table(name: &str) -> (&str, &str) {
    match name.split_once('.') {
        Some((schema, table)) => (schema, table),
        None => (DEFAULT_SCHEMA, name),
    }
}

/// How a column's values are protected.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransformKind {
    /// AES-256-GCM envelope, stored as BYTEA.
    #[default]
    Encrypt,
    /// FF1 format-preserving encryption over decimal digits, stored in the
    /// column's original text shape.
    Fpe,
    /// Irreversible deterministic HMAC token (hex), stored as text.
    Token,
    /// No crypto — writes pass through untouched. Only valid together with
    /// `mask`, for columns that should be masked but stay plaintext at rest.
    None,
}

/// One protected column.
///
/// Deserializes from the proxy's `[[column]]` table shape; in code, start from
/// [`ColumnPolicy::new`] and set the rest.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnPolicy {
    /// Table name, optionally schema-qualified; bare names mean `public`.
    pub table: String,
    /// Column name within the table.
    pub column: String,
    #[serde(default)]
    pub transform: TransformKind,
    /// Searchable columns carry a blind index before the envelope (stripped
    /// on read) and can be queried by equality. Only valid with
    /// [`TransformKind::Encrypt`].
    #[serde(default)]
    pub searchable: bool,
    /// Whether FPE values are detokenized on the read path. Only meaningful
    /// for [`TransformKind::Fpe`]; tokens are irreversible, envelopes always
    /// decrypt.
    #[serde(default = "default_true")]
    pub detokenize: bool,
    /// Read-path mask applied after decryption/detokenization.
    pub mask: Option<MaskSpec>,
}

fn default_true() -> bool {
    true
}

impl ColumnPolicy {
    /// An `encrypt`, non-searchable, unmasked column — the safe default.
    pub fn new(table: impl Into<String>, column: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            column: column.into(),
            transform: TransformKind::Encrypt,
            searchable: false,
            detokenize: true,
            mask: None,
        }
    }

    pub fn transform(mut self, transform: TransformKind) -> Self {
        self.transform = transform;
        self
    }

    pub fn searchable(mut self, searchable: bool) -> Self {
        self.searchable = searchable;
        self
    }

    pub fn detokenize(mut self, detokenize: bool) -> Self {
        self.detokenize = detokenize;
        self
    }

    pub fn mask(mut self, mask: MaskSpec) -> Self {
        self.mask = Some(mask);
        self
    }

    /// `(schema, table)` with the `public` default applied.
    pub fn schema_and_table(&self) -> (&str, &str) {
        split_table(&self.table)
    }

    /// The `schema.table.column` name — see the module docs for what it binds.
    pub fn qualified_name(&self) -> String {
        let (schema, table) = self.schema_and_table();
        format!("{schema}.{table}.{}", self.column)
    }
}

/// One table's declared row key, which binds each encrypted value to the row
/// it was written in (see [`crate::envelope::RowKey`]).
///
/// Opt-in per table because it is not free: whoever writes must be able to
/// name the row at both ends. Through the proxy that means client-supplied
/// key values, single-row updates and reads that project the key; in code it
/// means passing the row key to every seal and open.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TablePolicy {
    /// Table name, optionally schema-qualified; bare names mean `public`.
    pub table: String,
    /// The column whose value names a row. Must be unique per row — a primary
    /// key, or a column with a unique constraint. Nothing here can verify
    /// that: a non-unique choice silently weakens the binding to "some row in
    /// this group", which is why it is documented as the operator's assertion.
    pub row_key: String,
    /// Whether a stored value in this table's encrypted columns that carries
    /// *no* row binding is an error on read rather than back-compat.
    ///
    /// Off by default, which is what makes adopting `row_key` migration-free:
    /// values written before the key was declared keep opening. That tolerance
    /// is also what makes a degraded write invisible — a write that could not
    /// name one row seals cell-only, and the result is a ciphertext
    /// relocatable between rows for as long as the DEK lives, indistinguishable
    /// in the stored bytes from a pre-migration value.
    ///
    /// Turn this on once the table's pre-`row_key` values have been
    /// re-encrypted: back-compat then becomes a stated migration window rather
    /// than a permanent hole, and any later degradation is refused on the next
    /// read instead of going unnoticed.
    #[serde(default)]
    pub strict_row_binding: bool,
}

impl TablePolicy {
    pub fn new(table: impl Into<String>, row_key: impl Into<String>) -> Self {
        Self { table: table.into(), row_key: row_key.into(), strict_row_binding: false }
    }

    pub fn strict_row_binding(mut self, strict: bool) -> Self {
        self.strict_row_binding = strict;
        self
    }

    /// `(schema, table)` with the `public` default applied.
    pub fn schema_and_table(&self) -> (&str, &str) {
        split_table(&self.table)
    }
}

/// The whole policy: every protected column and every row-bound table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default, rename = "column")]
    pub columns: Vec<ColumnPolicy>,
    #[serde(default, rename = "table")]
    pub tables: Vec<TablePolicy>,
}

/// One table's declared row key, as [`Policy::row_keys`] hands it to whoever
/// resolves it against the catalog. Split from [`TablePolicy`] so a resolver
/// takes only what it needs.
#[derive(Debug, Clone)]
pub struct RowKeyDecl {
    pub schema: String,
    pub table: String,
    pub column: String,
}

/// A protected column with its transform wired: what [`Policy::build`]
/// produces and what every data path consumes.
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

impl Policy {
    pub fn new(columns: Vec<ColumnPolicy>, tables: Vec<TablePolicy>) -> Self {
        Self { columns, tables }
    }

    /// Refuses a policy that would look like protection while providing none.
    /// Every front end runs this before [`Self::build`].
    pub fn validate(&self) -> Result<(), Error> {
        let mut seen = HashSet::new();
        for column in &self.columns {
            let (schema, table) = column.schema_and_table();
            let name = column.qualified_name();
            if !seen.insert(name.clone()) {
                return Err(Error::Policy(format!("duplicate column entry for {name}")));
            }
            if column.searchable && column.transform != TransformKind::Encrypt {
                return Err(Error::Policy(format!(
                    "{name}: searchable requires transform = \"encrypt\""
                )));
            }
            if !column.detokenize && column.transform != TransformKind::Fpe {
                return Err(Error::Policy(format!(
                    "{name}: detokenize = false is only meaningful for transform = \"fpe\""
                )));
            }
            if column.transform == TransformKind::None && column.mask.is_none() {
                return Err(Error::Policy(format!(
                    "{name}: transform = \"none\" does nothing without a mask"
                )));
            }
            check_identifiers(&name, schema, table, &column.column)?;
        }
        self.validate_row_keys()
    }

    /// Checks every table's row-key declaration against the columns it would
    /// bind.
    ///
    /// Three of these refuse a configuration that would *look* like row
    /// binding while providing none of it, which is the failure worth being
    /// loud about: an operator who declares a row key believes cross-row
    /// relocation is detected, and a silent no-op leaves them believing it.
    fn validate_row_keys(&self) -> Result<(), Error> {
        let mut seen = HashSet::new();
        for entry in &self.tables {
            let (schema, table) = entry.schema_and_table();
            let qualified = format!("{schema}.{table}");
            if !seen.insert(qualified.clone()) {
                return Err(Error::Policy(format!("duplicate table entry for {qualified}")));
            }
            check_identifiers(&qualified, schema, table, &entry.row_key)?;

            let columns: Vec<&ColumnPolicy> = self
                .columns
                .iter()
                .filter(|column| column.schema_and_table() == (schema, table))
                .collect();
            if columns.is_empty() {
                return Err(Error::Policy(format!(
                    "table {qualified} declares row_key = \"{}\" but has no protected columns, \
                     so there is nothing to bind",
                    entry.row_key
                )));
            }
            // Only authenticated encryption has associated data to bind a row
            // into. FPE and tokenization map a plaintext to the same stored
            // bytes in every row — that determinism is what makes them
            // searchable and joinable — so a copy between rows of such a column
            // is indistinguishable from a legitimate write, whatever is
            // configured here.
            if !columns.iter().any(|column| column.transform == TransformKind::Encrypt) {
                return Err(Error::Policy(format!(
                    "table {qualified} declares row_key = \"{}\", but none of its columns use \
                     transform = \"encrypt\"; fpe and token values are identical in every row \
                     by design, so a row key would bind nothing",
                    entry.row_key
                )));
            }
            // The key column may itself be protected — but then reading it
            // back to verify a sibling would require opening a value that is
            // bound to the key being recovered.
            if columns.iter().any(|column| {
                column.column == entry.row_key && column.transform != TransformKind::None
            }) {
                return Err(Error::Policy(format!(
                    "table {qualified} declares row_key = \"{}\", which is itself a transformed \
                     column; the row key must be readable to verify the row it names",
                    entry.row_key
                )));
            }
        }
        Ok(())
    }

    /// The declared row keys, in policy order.
    pub fn row_keys(&self) -> Vec<RowKeyDecl> {
        self.tables
            .iter()
            .map(|entry| {
                let (schema, table) = entry.schema_and_table();
                RowKeyDecl {
                    schema: schema.to_owned(),
                    table: table.to_owned(),
                    column: entry.row_key.clone(),
                }
            })
            .collect()
    }

    /// Whether `schema.table` declares a row key whose migration window is
    /// closed. [`Self::validate`] refuses duplicate table entries, so the
    /// first match is the only one.
    fn strict_row_binding(&self, schema: &str, table: &str) -> bool {
        self.tables
            .iter()
            .find(|entry| entry.schema_and_table() == (schema, table))
            .is_some_and(|entry| entry.strict_row_binding)
    }

    /// Wires one transform per column. Deterministic keys (blind index, FPE,
    /// token HMAC) are named `schema.table.column` — the key source must carry
    /// that name — and the same string is the cell context every `encrypt`
    /// column binds into its envelopes (see the module docs).
    ///
    /// Does not validate; call [`Self::validate`] first.
    pub fn build(&self, keys: &Arc<dyn KeySource>) -> Vec<ProtectedColumn> {
        // One DEK cipher cache for the whole process: every encrypted column
        // shares the active key's schedule and, more importantly, its single
        // AES-GCM invocation budget (a per-column budget would let N columns
        // spend N times the random-nonce limit).
        let ciphers = Arc::new(Ciphers::new(keys.clone()));
        self.columns
            .iter()
            .map(|column| {
                let (schema, table) = column.schema_and_table();
                let key_name = column.qualified_name();
                let (transform, readable): (Option<Arc<dyn FieldTransform>>, bool) = match column
                    .transform
                {
                    TransformKind::Encrypt => {
                        let index_key = column.searchable.then(|| key_name.clone());
                        // The same `schema.table.column` that names the index
                        // key is bound into every envelope this column writes,
                        // so a ciphertext moved to another column stops
                        // authenticating. Both data paths reach this one
                        // transform for the column, so write and read always
                        // agree on the binding.
                        let context = CellContext::new(key_name);
                        // A closed migration window is the table's property,
                        // not the column's: it says every value in this
                        // table's encrypted columns is already row-bound, so
                        // one that is not is a degraded write rather than an
                        // old value.
                        let strict = self.strict_row_binding(schema, table);
                        let transform = EncryptTransform::new(ciphers.clone(), context, index_key)
                            .strict_row_binding(strict);
                        (Some(Arc::new(transform)), true)
                    }
                    TransformKind::Fpe => (
                        Some(Arc::new(FpeTransform::new(
                            keys.clone(),
                            key_name,
                            column.detokenize,
                        ))),
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
}

/// Refuses an identifier PostgreSQL could never carry, and warns about one it
/// would fold differently from how it is written.
fn check_identifiers(name: &str, schema: &str, table: &str, column: &str) -> Result<(), Error> {
    for (kind, ident) in [("schema", schema), ("table", table), ("column", column)] {
        if ident.len() > MAX_IDENTIFIER_BYTES {
            return Err(Error::Policy(format!(
                "{name}: {kind} name is {} bytes, and PostgreSQL truncates identifiers to \
                 {MAX_IDENTIFIER_BYTES}, so no table or column can carry it",
                ident.len()
            )));
        }
        if fold_identifier(ident, false) != ident {
            tracing::warn!(
                kind,
                ident,
                "configured identifier is not in the form PostgreSQL folds an unquoted name to; \
                 only a double-quoted SQL reference will match it"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::KeyId;
    use crate::envelope::RowKey;
    use crate::keys::Key;
    use crate::transform::WireForm;

    struct OneKey;

    const KEY_ID: KeyId = [1u8; 16];

    impl KeySource for OneKey {
        fn active_key(&self) -> Result<(KeyId, Key), Error> {
            Ok((KEY_ID, Key::new([2u8; 32])))
        }
        fn key(&self, id: &KeyId) -> Result<Key, Error> {
            if id == &KEY_ID {
                Ok(Key::new([2u8; 32]))
            } else {
                Err(Error::UnknownKey(hex::encode(id)))
            }
        }
        fn index_key(&self, _name: &str) -> Result<Key, Error> {
            Ok(Key::new([3u8; 32]))
        }
    }

    fn policy(toml: &str) -> Policy {
        toml::from_str(toml).expect("parses")
    }

    fn keys() -> Arc<dyn KeySource> {
        Arc::new(OneKey)
    }

    #[test]
    fn build_maps_kinds_to_transforms_and_readability() {
        let policy = policy(
            "[[column]]\ntable = \"users\"\ncolumn = \"email\"\nsearchable = true\n\
             \n[[column]]\ntable = \"cards\"\ncolumn = \"pan\"\ntransform = \"fpe\"\nmask = { keep_last = 4 }\n\
             \n[[column]]\ntable = \"cards\"\ncolumn = \"pin\"\ntransform = \"fpe\"\ndetokenize = false\n\
             \n[[column]]\ntable = \"users\"\ncolumn = \"ssn\"\ntransform = \"token\"\n\
             \n[[column]]\ntable = \"users\"\ncolumn = \"notes\"\ntransform = \"none\"\nmask = { keep_first = 1 }\n",
        );
        policy.validate().unwrap();
        let columns = policy.build(&keys());

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

    /// The programmatic constructors and the TOML shape reach the same policy.
    #[test]
    fn code_built_policy_matches_the_toml_shape() {
        let from_code = Policy::new(
            vec![
                ColumnPolicy::new("users", "email").searchable(true),
                ColumnPolicy::new("billing.cards", "pan")
                    .transform(TransformKind::Fpe)
                    .mask(MaskSpec { keep_first: 0, keep_last: 4, mask_with: '*' }),
            ],
            vec![TablePolicy::new("users", "id").strict_row_binding(true)],
        );
        let from_toml = policy(
            "[[column]]\ntable = \"users\"\ncolumn = \"email\"\nsearchable = true\n\
             \n[[column]]\ntable = \"billing.cards\"\ncolumn = \"pan\"\ntransform = \"fpe\"\nmask = { keep_last = 4 }\n\
             \n[[table]]\ntable = \"users\"\nrow_key = \"id\"\nstrict_row_binding = true\n",
        );
        for p in [&from_code, &from_toml] {
            p.validate().unwrap();
            assert_eq!(p.columns[0].qualified_name(), "public.users.email");
            assert!(p.columns[0].searchable);
            assert_eq!(p.columns[1].schema_and_table(), ("billing", "cards"));
            assert_eq!(p.columns[1].transform, TransformKind::Fpe);
            assert_eq!(p.columns[1].mask.unwrap().keep_last, 4);
            assert!(p.columns[1].detokenize);
            assert!(p.tables[0].strict_row_binding);
            let row_keys = p.row_keys();
            assert_eq!(row_keys.len(), 1);
            assert_eq!(
                (row_keys[0].schema.as_str(), row_keys[0].table.as_str()),
                ("public", "users")
            );
            assert_eq!(row_keys[0].column, "id");
        }
    }

    /// Two encrypted columns share one DEK, so only the per-column binding
    /// stops stored bytes being moved from one into the other. This pins the
    /// wiring: the transform each column gets is bound to *its* name.
    #[test]
    fn each_encrypted_column_is_bound_to_its_own_name() {
        let policy = policy(
            "[[column]]\ntable = \"users\"\ncolumn = \"ssn\"\n\
             \n[[column]]\ntable = \"users\"\ncolumn = \"credit_card\"\n",
        );
        let columns = policy.build(&keys());

        let ssn = columns[0].transform.as_ref().expect("encrypt column has a transform");
        let card = columns[1].transform.as_ref().expect("encrypt column has a transform");

        let stored = ssn.seal(b"078-05-1120", None).unwrap();
        assert!(
            matches!(card.open(&stored, None), Err(Error::Decrypt)),
            "an ssn value pasted into credit_card must not authenticate"
        );
        assert_eq!(ssn.open(&stored, None).unwrap().unwrap(), b"078-05-1120");
    }

    /// `strict_row_binding` is declared on the table but enforced by the
    /// per-column transform, so the wiring between the two is what makes the
    /// setting mean anything. Only the strict table's columns get it.
    #[test]
    fn strict_row_binding_reaches_only_its_own_tables_transforms() {
        let policy = policy(
            "[[column]]\ntable = \"users\"\ncolumn = \"ssn\"\n\
             \n[[column]]\ntable = \"orders\"\ncolumn = \"note\"\n\
             \n[[table]]\ntable = \"users\"\nrow_key = \"id\"\nstrict_row_binding = true\n\
             \n[[table]]\ntable = \"orders\"\nrow_key = \"id\"\n",
        );
        policy.validate().unwrap();
        let columns = policy.build(&keys());
        let row = RowKey::new(b"42".to_vec());

        let ssn = columns[0].transform.as_ref().expect("encrypt column has a transform");
        let note = columns[1].transform.as_ref().expect("encrypt column has a transform");

        // A cell-only value is what a degraded write leaves behind.
        let degraded_ssn = ssn.seal(b"078-05-1120", None).unwrap();
        assert!(
            matches!(ssn.open(&degraded_ssn, Some(&row)), Err(Error::RowBindingDowngraded)),
            "the strict table's column must refuse an unbound value"
        );

        // The other table's window is still open, so the same shape opens.
        let degraded_note = note.seal(b"gift", None).unwrap();
        assert_eq!(note.open(&degraded_note, Some(&row)).unwrap().unwrap(), b"gift");
    }

    #[test]
    fn column_rules_are_refused() {
        for (name, toml) in [
            (
                "duplicate column",
                "[[column]]\ntable = \"users\"\ncolumn = \"a\"\n[[column]]\ntable = \"public.users\"\ncolumn = \"a\"\n",
            ),
            (
                "searchable fpe",
                "[[column]]\ntable = \"cards\"\ncolumn = \"pan\"\ntransform = \"fpe\"\nsearchable = true\n",
            ),
            (
                "detokenize=false on encrypt",
                "[[column]]\ntable = \"users\"\ncolumn = \"email\"\ndetokenize = false\n",
            ),
            ("none without mask", "[[column]]\ntable = \"users\"\ncolumn = \"notes\"\ntransform = \"none\"\n"),
            (
                "identifier too long",
                &format!("[[column]]\ntable = \"users\"\ncolumn = \"{}\"\n", "x".repeat(64)),
            ),
        ] {
            assert!(matches!(policy(toml).validate(), Err(Error::Policy(_))), "{name}");
        }
    }

    #[test]
    fn a_row_key_that_would_bind_nothing_is_refused() {
        for (name, columns, tables) in [
            ("no columns on the table", "", "[[table]]\ntable = \"users\"\nrow_key = \"id\"\n"),
            (
                "only deterministic columns",
                "[[column]]\ntable = \"users\"\ncolumn = \"ssn\"\ntransform = \"token\"\n",
                "[[table]]\ntable = \"users\"\nrow_key = \"id\"\n",
            ),
            (
                "the key column is itself transformed",
                "[[column]]\ntable = \"users\"\ncolumn = \"id\"\n",
                "[[table]]\ntable = \"users\"\nrow_key = \"id\"\n",
            ),
            (
                "duplicate table",
                "[[column]]\ntable = \"users\"\ncolumn = \"ssn\"\n",
                "[[table]]\ntable = \"users\"\nrow_key = \"id\"\n[[table]]\ntable = \"public.users\"\nrow_key = \"id\"\n",
            ),
        ] {
            let p = policy(&format!("{columns}{tables}"));
            assert!(matches!(p.validate(), Err(Error::Policy(_))), "{name}");
        }
    }

    #[test]
    fn a_row_key_is_accepted_when_any_column_can_bind_it() {
        let p = policy(
            "[[column]]\ntable = \"users\"\ncolumn = \"ssn\"\ntransform = \"token\"\n\
             [[column]]\ntable = \"users\"\ncolumn = \"email\"\n\
             [[column]]\ntable = \"users\"\ncolumn = \"id\"\ntransform = \"none\"\nmask = { keep_last = 2 }\n\
             [[table]]\ntable = \"users\"\nrow_key = \"id\"\n",
        );
        p.validate().unwrap();
    }
}
