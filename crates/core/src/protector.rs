//! [`Protector`] — the library's front door: seal, open, search and mask by
//! column name, over a validated [`Policy`] and a [`KeySource`].
//!
//! This is the code-time counterpart of the proxy. Both build their transforms
//! through [`Policy::build`], so a value sealed here opens through the proxy
//! and vice versa; what differs is who names the column and the row. The
//! proxy reads them off the SQL and the result set, and an application calling
//! this type names them itself — which is exactly where hand-wired code goes
//! wrong, so every way of getting it wrong is an error here rather than a
//! degraded seal:
//!
//! - a column the policy does not name is [`Error::UnknownColumn`], never a
//!   passthrough that stores plaintext;
//! - a row-bound column sealed or opened with no row key is
//!   [`Error::RowKeyRequired`], never a cell-only seal that can later be moved
//!   between rows;
//! - a row key passed to a column whose table declares none is
//!   [`Error::RowKeyNotDeclared`], never an envelope the proxy cannot open;
//! - a value that carries none of its column's stored forms comes back as
//!   [`Opened::Unprotected`], a variant the caller has to name, never as a
//!   plaintext indistinguishable from an opened one.
//!
//! # Searching
//!
//! A `searchable` column stores a 32-byte blind index ahead of the envelope.
//! [`Protector::search_term`] computes that index for a plaintext; the
//! predicate to write against the stored column is
//!
//! ```sql
//! substring(email from 1 for 32) = $1
//! ```
//!
//! which is the same rewrite the proxy applies to `email = $1`. FPE and token
//! columns are deterministic, so equality on them is `phone = $1` with the
//! *sealed* value bound — [`Protector::seal`] is the search term there, and
//! [`Protector::search_term`] returns `None` to say so.
//!
//! # What this does not protect
//!
//! Deterministic transforms (blind index, FPE, tokens) leak equality: two rows
//! with the same plaintext store the same bytes, and frequency analysis works
//! on them. Masking only happens where [`Protector::mask`] is called. Neither
//! is a limitation of this type; both are what the transforms are.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use crate::envelope::RowKey;
use crate::keys::KeySource;
use crate::policy::{split_table, Policy, ProtectedColumn};
use crate::transform::WireForm;
use crate::Error;

/// One column, with what the policy says about its row.
struct Column {
    spec: ProtectedColumn,
    /// Whether the column's table declares a `row_key`. Decides which of
    /// `Some(row)` / `None` is the error for this column.
    row_bound: bool,
}

/// Seals, opens, searches and masks by column name. See the module docs.
pub struct Protector {
    columns: HashMap<String, Column>,
}

/// What [`Protector::open`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "an Unprotected value is plaintext that was never sealed; decide what that means"]
pub enum Opened {
    /// The column's transform reversed the stored form.
    Value(Vec<u8>),
    /// The stored bytes carried none of the column's protected forms: a
    /// value written before the column was protected, or a mask-only
    /// (`transform = "none"`) column. Returned as-is.
    Unprotected(Vec<u8>),
}

impl Opened {
    /// The bytes either way, for a caller mid-migration that accepts both.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Value(bytes) | Self::Unprotected(bytes) => bytes,
        }
    }

    /// The opened value, refusing an unprotected one — what a caller wants
    /// once every value in the column is known to be sealed. `column` names
    /// the column in the error.
    pub fn into_value(self, column: &str) -> Result<Vec<u8>, Error> {
        match self {
            Self::Value(bytes) => Ok(bytes),
            Self::Unprotected(_) => Err(Error::Unprotected(column.to_owned())),
        }
    }
}

impl Protector {
    /// Validates the policy and wires one transform per column.
    ///
    /// Refuses with [`Error::Policy`] what the proxy would refuse at startup.
    /// Keys are not touched here: a missing deterministic key surfaces from
    /// the first seal or search that needs it, as [`Error::UnknownKey`].
    pub fn new(policy: Policy, keys: Arc<dyn KeySource>) -> Result<Self, Error> {
        policy.validate()?;
        let row_bound: std::collections::HashSet<(String, String)> = policy
            .tables
            .iter()
            .map(|table| {
                let (schema, table) = table.schema_and_table();
                (schema.to_owned(), table.to_owned())
            })
            .collect();
        let columns = policy
            .build(&keys)
            .into_iter()
            .map(|spec| {
                let bound = row_bound.contains(&(spec.schema.clone(), spec.table.clone()));
                (spec.qualified_name(), Column { spec, row_bound: bound })
            })
            .collect();
        Ok(Self { columns })
    }

    /// The qualified names of every column this protector covers.
    pub fn columns(&self) -> impl Iterator<Item = &str> {
        self.columns.keys().map(String::as_str)
    }

    /// The wired spec for a column: its transform, wire form, mask.
    pub fn column(&self, name: &str) -> Result<&ProtectedColumn, Error> {
        self.lookup(name).map(|column| &column.spec)
    }

    /// Which shape the stored value takes — BYTEA for envelopes, the
    /// original text shape for FPE and tokens. `None` for a mask-only column.
    pub fn wire(&self, name: &str) -> Result<Option<WireForm>, Error> {
        Ok(self.column(name)?.transform.as_ref().map(|transform| transform.wire()))
    }

    /// Whether a column's table declares a `row_key`, so seal and open need
    /// one.
    pub fn binds_row(&self, name: &str) -> Result<bool, Error> {
        self.lookup(name).map(|column| column.row_bound)
    }

    /// A plaintext's stored form for `column`.
    ///
    /// `row` is required for a column whose table declares a `row_key` and
    /// refused for one whose table does not. A mask-only column returns the
    /// plaintext unchanged: its policy is plaintext at rest.
    pub fn seal(
        &self,
        column: &str,
        plaintext: &[u8],
        row: Option<&RowKey>,
    ) -> Result<Vec<u8>, Error> {
        let entry = self.lookup(column)?;
        entry.check_row(column, row)?;
        match &entry.spec.transform {
            Some(transform) => transform.seal(plaintext, row),
            None => Ok(plaintext.to_vec()),
        }
    }

    /// Reverses [`Self::seal`]. Same row-key rules; a column whose stored form
    /// is irreversible (tokens, FPE with `detokenize = false`) is
    /// [`Error::NotReadable`].
    pub fn open(&self, column: &str, stored: &[u8], row: Option<&RowKey>) -> Result<Opened, Error> {
        let entry = self.lookup(column)?;
        entry.check_row(column, row)?;
        let Some(transform) = &entry.spec.transform else {
            return Ok(Opened::Unprotected(stored.to_vec()));
        };
        if !entry.spec.readable {
            return Err(Error::NotReadable(column.to_owned()));
        }
        Ok(match transform.open(stored, row)? {
            Some(value) => Opened::Value(value),
            None => Opened::Unprotected(stored.to_vec()),
        })
    }

    /// The blind index `plaintext` is stored under in a `searchable` column —
    /// bind it to `substring(col from 1 for 32) = $1`. `None` for a column
    /// that is not searchable, so a caller cannot build a predicate that
    /// matches nothing; for FPE and token columns compare against
    /// [`Self::seal`] instead, which is deterministic.
    pub fn search_term(&self, column: &str, plaintext: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match &self.lookup(column)?.spec.transform {
            Some(transform) => transform.search_index(plaintext),
            None => Ok(None),
        }
    }

    /// Applies the column's read-path mask, if it declares one. Borrowed when
    /// there is nothing to do.
    pub fn mask<'a>(&self, column: &str, value: &'a [u8]) -> Result<Cow<'a, [u8]>, Error> {
        Ok(match self.column(column)?.mask {
            Some(mask) => Cow::Owned(mask.apply(value)),
            None => Cow::Borrowed(value),
        })
    }

    /// `schema.table.column`, or `table.column` with the `public` default.
    fn lookup(&self, name: &str) -> Result<&Column, Error> {
        let key: Cow<'_, str> = match name.matches('.').count() {
            1 => {
                let (table, column) = name.split_once('.').expect("one dot");
                let (schema, table) = split_table(table);
                Cow::Owned(format!("{schema}.{table}.{column}"))
            }
            _ => Cow::Borrowed(name),
        };
        self.columns.get(key.as_ref()).ok_or_else(|| Error::UnknownColumn(name.to_owned()))
    }
}

impl Column {
    fn check_row(&self, name: &str, row: Option<&RowKey>) -> Result<(), Error> {
        match (self.row_bound, row) {
            (true, None) => Err(Error::RowKeyRequired(name.to_owned())),
            (false, Some(_)) => Err(Error::RowKeyNotDeclared(name.to_owned())),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::KeyId;
    use crate::keys::Key;
    use crate::mask::MaskSpec;
    use crate::policy::{ColumnPolicy, TablePolicy, TransformKind};

    struct OneKey;
    const KEY_ID: KeyId = [9u8; 16];

    impl KeySource for OneKey {
        fn active_key(&self) -> Result<(KeyId, Key), Error> {
            Ok((KEY_ID, Key::new([2u8; 32])))
        }
        fn key(&self, id: &KeyId) -> Result<Key, Error> {
            (id == &KEY_ID).then(|| Key::new([2u8; 32])).ok_or(Error::Decrypt)
        }
        fn index_key(&self, _name: &str) -> Result<Key, Error> {
            Ok(Key::new([3u8; 32]))
        }
    }

    fn protector() -> Protector {
        let policy =
            Policy::new(
                vec![
                    ColumnPolicy::new("users", "email").searchable(true),
                    ColumnPolicy::new("users", "ssn").transform(TransformKind::Token),
                    ColumnPolicy::new("users", "note")
                        .transform(TransformKind::None)
                        .mask(MaskSpec { keep_first: 2, keep_last: 0, mask_with: '*' }),
                    ColumnPolicy::new("billing.cards", "pan")
                        .transform(TransformKind::Fpe)
                        .mask(MaskSpec { keep_first: 0, keep_last: 4, mask_with: '*' }),
                    ColumnPolicy::new("billing.cards", "cvv")
                        .transform(TransformKind::Fpe)
                        .detokenize(false),
                ],
                vec![TablePolicy::new("users", "id")],
            );
        Protector::new(policy, Arc::new(OneKey)).unwrap()
    }

    #[test]
    fn an_invalid_policy_is_refused_at_construction() {
        let policy = Policy::new(
            vec![ColumnPolicy::new("users", "ssn").transform(TransformKind::Token)],
            vec![TablePolicy::new("users", "id")],
        );
        assert!(matches!(Protector::new(policy, Arc::new(OneKey)), Err(Error::Policy(_))));
    }

    #[test]
    fn an_unknown_column_is_an_error_not_a_passthrough() {
        let p = protector();
        assert!(matches!(p.seal("users.emial", b"x", None), Err(Error::UnknownColumn(_))));
        assert!(matches!(p.open("public.users.nope", b"x", None), Err(Error::UnknownColumn(_))));
        assert!(matches!(p.search_term("users.nope", b"x"), Err(Error::UnknownColumn(_))));
        assert!(matches!(p.mask("users.nope", b"x"), Err(Error::UnknownColumn(_))));
    }

    #[test]
    fn a_row_bound_column_refuses_a_missing_row_key() {
        let p = protector();
        assert!(matches!(p.seal("users.email", b"a@b.io", None), Err(Error::RowKeyRequired(_))));
        let row = RowKey::from_i64(7);
        let stored = p.seal("users.email", b"a@b.io", Some(&row)).unwrap();
        assert!(matches!(p.open("users.email", &stored, None), Err(Error::RowKeyRequired(_))));
        assert_eq!(
            p.open("users.email", &stored, Some(&row)).unwrap(),
            Opened::Value(b"a@b.io".to_vec())
        );
        // Moved to another row, it no longer authenticates.
        assert!(matches!(
            p.open("users.email", &stored, Some(&RowKey::from_i64(8))),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn a_row_key_on_an_unbound_column_is_refused() {
        let p = protector();
        let row = RowKey::from_i64(7);
        assert!(matches!(
            p.seal("billing.cards.pan", b"4111111111111111", Some(&row)),
            Err(Error::RowKeyNotDeclared(_))
        ));
    }

    #[test]
    fn names_resolve_with_and_without_the_default_schema() {
        let p = protector();
        assert!(p.column("users.email").is_ok());
        assert!(p.column("public.users.email").is_ok());
        assert!(p.column("billing.cards.pan").is_ok());
        assert!(matches!(p.column("cards.pan"), Err(Error::UnknownColumn(_))));
        assert!(p.binds_row("users.email").unwrap());
        assert!(!p.binds_row("billing.cards.pan").unwrap());
    }

    #[test]
    fn search_term_is_the_stored_blind_index_and_none_elsewhere() {
        let p = protector();
        let row = RowKey::from_i64(1);
        let stored = p.seal("users.email", b"a@b.io", Some(&row)).unwrap();
        let term = p.search_term("users.email", b"a@b.io").unwrap().expect("searchable");
        assert_eq!(term.len(), 32);
        assert_eq!(&stored[..32], &term[..], "the predicate matches the stored prefix");
        assert_eq!(p.search_term("billing.cards.pan", b"4111111111111111").unwrap(), None);
        assert_eq!(p.search_term("users.note", b"x").unwrap(), None);
    }

    #[test]
    fn irreversible_columns_seal_but_refuse_to_open() {
        let p = protector();
        let token = p.seal("users.ssn", b"078-05-1120", Some(&RowKey::from_i64(1)));
        let token = token.unwrap();
        assert_ne!(token, b"078-05-1120");
        assert!(matches!(
            p.open("users.ssn", &token, Some(&RowKey::from_i64(1))),
            Err(Error::NotReadable(_))
        ));
        let cvv = p.seal("billing.cards.cvv", b"123456", None).unwrap();
        assert!(matches!(p.open("billing.cards.cvv", &cvv, None), Err(Error::NotReadable(_))));
    }

    #[test]
    fn fpe_is_deterministic_so_seal_is_its_search_term() {
        let p = protector();
        let a = p.seal("billing.cards.pan", b"4111-1111-1111-1111", None).unwrap();
        let b = p.seal("billing.cards.pan", b"4111-1111-1111-1111", None).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), b"4111-1111-1111-1111".len(), "format preserved");
        assert_eq!(
            p.open("billing.cards.pan", &a, None).unwrap(),
            Opened::Value(b"4111-1111-1111-1111".to_vec())
        );
        assert_eq!(p.wire("billing.cards.pan").unwrap(), Some(WireForm::Text));
        assert_eq!(p.wire("users.email").unwrap(), Some(WireForm::Bytea));
        assert_eq!(p.wire("users.note").unwrap(), None);
    }

    #[test]
    fn unprotected_values_are_named_not_hidden() {
        let p = protector();
        let row = RowKey::from_i64(1);
        // Pre-migration plaintext in an encrypted column.
        let opened = p.open("users.email", b"legacy@b.io", Some(&row)).unwrap();
        assert_eq!(opened, Opened::Unprotected(b"legacy@b.io".to_vec()));
        assert!(matches!(opened.clone().into_value("users.email"), Err(Error::Unprotected(_))));
        assert_eq!(opened.into_bytes(), b"legacy@b.io");
        // A mask-only column is plaintext at rest by policy.
        assert_eq!(p.seal("users.note", b"hello", Some(&row)).unwrap(), b"hello");
        assert_eq!(
            p.open("users.note", b"hello", Some(&row)).unwrap(),
            Opened::Unprotected(b"hello".to_vec())
        );
    }

    #[test]
    fn mask_applies_only_where_declared() {
        let p = protector();
        assert_eq!(p.mask("users.note", b"hello").unwrap().as_ref(), b"he***");
        assert_eq!(
            p.mask("billing.cards.pan", b"4111111111111111").unwrap().as_ref(),
            b"************1111"
        );
        assert!(matches!(p.mask("users.email", b"a@b.io").unwrap(), Cow::Borrowed(_)));
    }
}
