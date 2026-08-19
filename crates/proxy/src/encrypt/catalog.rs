//! The write path's view of which columns are protected.
//!
//! Keyed by **name** — `(schema, table) → column → transform` — because that
//! is all a SQL statement carries. The read path keys the same columns by
//! `(table_oid, attnum)` instead, which is why a migration can move a column
//! out from under one direction and not the other; see `crate::rows`.
//!
//! Two lookups that read alike answer different questions. [`WriteCatalog::table`]
//! answers "does a write here need sealing", so a mask-only column is absent
//! from it: writing plaintext to one is correct. [`WriteCatalog::protects_reads`]
//! answers "does reading this hand the client something the read path must act
//! on", where a mask-only column is exactly the case that matters.
//! [`WriteCatalog::scoped`] hands out both at once, which is what lets a
//! `TableScope` resolve a predicate against the write direction and a
//! projection against the read one without asking twice.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dbsec_core::transform::FieldTransform;
use sqlparser::ast::{Ident, ObjectName};

use crate::columns::ProtectedColumn;
use crate::config::{fold_identifier, OnUnprotected};

/// The protected columns of one table, keyed by column name.
pub(super) type Columns = HashMap<String, Arc<dyn FieldTransform>>;

/// The names of one table's columns the *read* path protects — the
/// transformed ones and the mask-only ones alike.
///
/// A superset of [`Columns`]' keys, and the reason it exists: a mask-only
/// column has no transform, so it is absent from `Columns` by design, yet
/// reading it is exactly the case the read path must act on.
pub(super) type ReadColumns = HashSet<String>;

/// Protected columns keyed by name for SQL matching:
/// `(schema, table) → column → transform`.
pub struct WriteCatalog {
    tables: HashMap<(String, String), Columns>,
    /// Protected table names without their schema, so an unqualified SQL name
    /// can be recognised as *possibly* protected even when `search_path` no
    /// longer says which schema it resolves to.
    bare_names: HashSet<String>,
    /// The columns the *read* path has something to do to, keyed by table.
    /// A superset of `tables`: a mask-only column has no transform, so it is
    /// not in the write catalog at all, but the mask applied on the way out is
    /// the only thing protecting it. See [`Self::protects_reads`].
    read_columns: HashMap<(String, String), ReadColumns>,
    /// The `bare_names` of `read_columns`' tables.
    read_bare_names: HashSet<String>,
    /// Handed out for a table that protects reads but has nothing to seal, so
    /// [`Self::scoped`] can answer with a `&Columns` without the caller having
    /// to special-case a table whose only protection is a mask.
    no_columns: Columns,
    /// The `no_columns` of the read direction, for [`Self::read_columns_of`].
    no_read_columns: ReadColumns,
    pub(super) on_unprotected: OnUnprotected,
}

impl WriteCatalog {
    pub fn new(columns: &[ProtectedColumn], on_unprotected: OnUnprotected) -> Self {
        let mut tables: HashMap<_, Columns> = HashMap::new();
        let mut bare_names = HashSet::new();
        let mut read_columns: HashMap<_, ReadColumns> = HashMap::new();
        let mut read_bare_names = HashSet::new();
        for column in columns {
            // Every configured column protects the read path somehow: config
            // validation refuses `transform = "none"` without a mask, so a
            // column with no transform always carries one.
            read_bare_names.insert(column.table.clone());
            read_columns
                .entry((column.schema.clone(), column.table.clone()))
                .or_default()
                .insert(column.column.clone());
            // Mask-only columns have no transform; their writes pass through.
            let Some(transform) = &column.transform else { continue };
            bare_names.insert(column.table.clone());
            tables
                .entry((column.schema.clone(), column.table.clone()))
                .or_default()
                .insert(column.column.clone(), transform.clone());
        }
        Self {
            tables,
            bare_names,
            read_columns,
            read_bare_names,
            no_columns: Columns::new(),
            no_read_columns: ReadColumns::new(),
            on_unprotected,
        }
    }

    /// Looks a table up the way Postgres would resolve the SQL name: the last
    /// identifier is the table, the one before it the schema, and bare names
    /// fall back to `public` — which holds only while the session's
    /// `search_path` does, hence
    /// [`QueryRewriter::table`](super::QueryRewriter::table).
    pub(super) fn table(&self, name: &ObjectName) -> Option<&Columns> {
        self.tables.get(&resolved_name(name)?)
    }

    /// Whether an unqualified name matches a protected table in *some* schema.
    pub(super) fn may_be_protected(&self, name: &ObjectName) -> bool {
        name.0.last().is_some_and(|ident| self.bare_names.contains(&normalize(ident)))
    }

    /// Whether reading this table hands the client something the read path is
    /// supposed to act on — a transform to open, a mask to apply, or both.
    ///
    /// Deliberately *not* [`Self::table`]. That lookup answers "does a write
    /// here need sealing", and a plaintext write to a mask-only column is
    /// correct, so the mask-only case is absent from it by design. Reading one
    /// is the opposite: the value is stored in the clear and the mask is the
    /// only thing that ever hides it, so a path that streams the stored bytes
    /// past the read path — `COPY … TO`, in either of its two forms — hands
    /// the client exactly what the mask exists to withhold.
    pub(super) fn protects_reads(&self, name: &ObjectName) -> bool {
        resolved_name(name).is_some_and(|key| self.read_columns.contains_key(&key))
    }

    /// The read direction of one table on its own, empty when the table
    /// protects no reads. For a caller that already resolved the write
    /// direction and only needs the other half.
    pub(super) fn read_columns_of(&self, name: &ObjectName) -> &ReadColumns {
        resolved_name(name)
            .and_then(|key| self.read_columns.get(&key))
            .unwrap_or(&self.no_read_columns)
    }

    /// Both directions of one table at once, for building a `TableScope`.
    ///
    /// A scope answers two different questions about the same statement —
    /// "which transform seals this predicate" (write direction) and "does
    /// projecting this hand the client something the read path must act on"
    /// (read direction) — so it needs both halves, and needs them from a
    /// single lookup: two would report an unresolvable `search_path` twice for
    /// one name. `None` means the table is protected in neither direction;
    /// a table protected only by a mask answers with an empty [`Columns`],
    /// because a plaintext write to it is correct.
    pub(super) fn scoped(&self, name: &ObjectName) -> Option<(&Columns, &ReadColumns)> {
        let key = resolved_name(name)?;
        let read = self.read_columns.get(&key)?;
        Some((self.tables.get(&key).unwrap_or(&self.no_columns), read))
    }

    /// [`Self::may_be_protected`] for the read direction.
    pub(super) fn may_protect_reads(&self, name: &ObjectName) -> bool {
        name.0.last().is_some_and(|ident| self.read_bare_names.contains(&normalize(ident)))
    }
}

/// A SQL table name as the catalog keys it: `(schema, table)`, with an
/// unqualified name resolved against `public`.
pub(super) fn resolved_name(name: &ObjectName) -> Option<(String, String)> {
    let mut parts = name.0.iter().rev();
    let table = normalize(parts.next()?);
    let schema = parts.next().map_or_else(|| "public".to_owned(), normalize);
    Some((schema, table))
}

/// One SQL identifier as the catalog holds it — folded by the same
/// [`crate::config::fold_identifier`] that config validation checks the
/// configured names against, so the two sides of every name comparison cannot
/// drift apart. See that function for the two rules and why Rust's own answer
/// differs from the server's.
pub(super) fn normalize(ident: &Ident) -> String {
    fold_identifier(&ident.value, ident.quote_style.is_some()).into_owned()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::config::OnUnprotected;
    use crate::encrypt::tests::*;
    use crate::encrypt::WriteCatalog;
    use crate::rows::tests::transform;

    /// Rust's `to_lowercase` folds `Ä` to `ä` and the Kelvin sign to `k`;
    /// PostgreSQL leaves every multibyte character in an unquoted identifier
    /// alone. Folding the proxy's way meant a protected column named with a
    /// non-ASCII letter never matched, and the write went through in plaintext.
    #[test]
    fn a_non_ascii_column_name_is_folded_the_way_postgres_folds_it() {
        let catalog = Arc::new(WriteCatalog::new(
            &[column("Ämail", transform(false), false)],
            OnUnprotected::Warn,
        ));
        let mut rewriter = rewriter(catalog);
        // Written unquoted and with the ASCII half in a different case, which
        // is exactly what the server folds and what it does not.
        let sql = rewritten_query(&mut rewriter, "INSERT INTO users (ÄMAIL) VALUES ('a@b.io')")
            .expect("rewritten");
        assert!(!sql.contains("a@b.io"), "{sql}");
        assert_eq!(open_hex_literal(&sql, false), b"a@b.io");
    }

    /// PostgreSQL truncates every identifier to 63 bytes, so a longer name in
    /// a query refers to the truncated catalog entry. Matching the untruncated
    /// name meant the write was treated as unprotected.
    #[test]
    fn an_over_long_identifier_matches_the_name_postgres_truncated_it_to() {
        let stored = "e".repeat(crate::config::MAX_IDENTIFIER_BYTES);
        let catalog = Arc::new(WriteCatalog::new(
            &[column(&stored, transform(false), false)],
            OnUnprotected::Warn,
        ));
        let mut rewriter = rewriter(catalog);
        let written = format!("{stored}toolong");
        let sql = rewritten_query(
            &mut rewriter,
            &format!("INSERT INTO users ({written}) VALUES ('a@b.io')"),
        )
        .expect("rewritten");
        assert_eq!(open_hex_literal(&sql, false), b"a@b.io");
    }
}
