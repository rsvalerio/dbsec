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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dbsec_core::transform::FieldTransform;
use sqlparser::ast::{Ident, ObjectName};

use crate::columns::ProtectedColumn;
use crate::config::{fold_identifier, OnUnprotected};

/// The protected columns of one table, keyed by column name.
pub(super) type Columns = HashMap<String, Arc<dyn FieldTransform>>;

/// Protected columns keyed by name for SQL matching:
/// `(schema, table) → column → transform`.
pub struct WriteCatalog {
    tables: HashMap<(String, String), Columns>,
    /// Protected table names without their schema, so an unqualified SQL name
    /// can be recognised as *possibly* protected even when `search_path` no
    /// longer says which schema it resolves to.
    bare_names: HashSet<String>,
    /// The tables the *read* path has something to do to, which is a superset
    /// of `tables`: a mask-only column has no transform, so it is not in the
    /// write catalog at all, but the mask applied on the way out is the only
    /// thing protecting it. See [`Self::protects_reads`].
    read_tables: HashSet<(String, String)>,
    /// The `bare_names` of `read_tables`.
    read_bare_names: HashSet<String>,
    pub(super) on_unprotected: OnUnprotected,
}

impl WriteCatalog {
    pub fn new(columns: &[ProtectedColumn], on_unprotected: OnUnprotected) -> Self {
        let mut tables: HashMap<_, Columns> = HashMap::new();
        let mut bare_names = HashSet::new();
        let mut read_tables = HashSet::new();
        let mut read_bare_names = HashSet::new();
        for column in columns {
            // Every configured column protects the read path somehow: config
            // validation refuses `transform = "none"` without a mask, so a
            // column with no transform always carries one.
            read_bare_names.insert(column.table.clone());
            read_tables.insert((column.schema.clone(), column.table.clone()));
            // Mask-only columns have no transform; their writes pass through.
            let Some(transform) = &column.transform else { continue };
            bare_names.insert(column.table.clone());
            tables
                .entry((column.schema.clone(), column.table.clone()))
                .or_default()
                .insert(column.column.clone(), transform.clone());
        }
        Self { tables, bare_names, read_tables, read_bare_names, on_unprotected }
    }

    /// Looks a table up the way Postgres would resolve the SQL name: the last
    /// identifier is the table, the one before it the schema, and bare names
    /// fall back to `public` — which holds only while the session's
    /// `search_path` does, hence [`QueryRewriter::table`].
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
        resolved_name(name).is_some_and(|key| self.read_tables.contains(&key))
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
