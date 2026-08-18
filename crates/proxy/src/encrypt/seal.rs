//! Sealing a value into the cell it is being written to.
//!
//! Everything that decides *what bytes reach the column*: which row a
//! statement writes (so a row-bound value can be sealed against it), how an
//! `INSERT`'s values and an assignment list are walked, and the single choke
//! point where a plaintext becomes a stored form.
//!
//! A second `impl QueryRewriter` block rather than free functions: these are
//! the rewriter's own decisions and they read `self.catalog`, `self.rows` and
//! the `on_unprotected` policy. Splitting them out is about what a reviewer
//! has to hold at once, not about decoupling them from the rewriter.

use std::sync::Arc;

use dbsec_core::transform::{FieldTransform, WireForm};
use sqlparser::ast::{
    Assignment, AssignmentTarget, Expr, Ident, Insert, ObjectName, SetExpr, Value,
};

use super::catalog::{normalize, resolved_name, Columns};
use super::scope::{column_name, expr_shape};
use super::{
    literal_plaintext, placeholder_index, unwrap_casts, AssignmentScope, QueryRewriter, Rejection,
    SealTarget, SealedValues, Unprotected,
};
use crate::portal::{ParamTransforms, RowKeySource};
use crate::rowkey;
use crate::rows::ResolvedRowKey;

impl QueryRewriter {
    /// The row an `UPDATE` writes, read out of its `WHERE`.
    ///
    /// Only `row_key = <literal|parameter>`, and only reachable through a chain
    /// of `AND`s. That is not conservatism for its own sake: a Bind carries one
    /// byte string per placeholder, so `UPDATE users SET ssn = $1 WHERE dept =
    /// 'x'` would need a *different* ciphertext for every matching row and
    /// there is nowhere to put them. An `OR`, an `IN`, or a range names a set
    /// of rows, and a set has no single key to bind. Those are refusals rather
    /// than silent cell-only writes, because a value stored bound to the wrong
    /// row — or to none — never opens again.
    pub(super) fn row_key_in_predicate(
        &self,
        expr: &Expr,
        spec: &ResolvedRowKey,
    ) -> Option<RowKeySource> {
        use sqlparser::ast::BinaryOperator;
        match expr {
            Expr::BinaryOp { left, op: BinaryOperator::And, right } => self
                .row_key_in_predicate(left, spec)
                .or_else(|| self.row_key_in_predicate(right, spec)),
            Expr::Nested(inner) => self.row_key_in_predicate(inner, spec),
            Expr::BinaryOp { left, op: BinaryOperator::Eq, right } => {
                let wanted = spec.name.to_lowercase();
                let names = |e: &Expr| column_name(e).is_some_and(|name| name == wanted);
                if names(left) {
                    self.row_key_source(right, spec)
                } else if names(right) {
                    self.row_key_source(left, spec)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// The declared row key for a table, if it has one.
    ///
    /// `None` covers both "no `[[table]]` entry" and "no read context", and
    /// both mean cell-only binding — the behaviour before row keys existed.
    pub(super) fn row_key_spec(&self, schema: &str, table: &str) -> Option<ResolvedRowKey> {
        let rows = self.rows.as_ref()?;
        let key = (schema.to_lowercase(), table.to_lowercase());
        rows.resolved().row_key_by_table.get(&key).cloned()
    }

    /// Turns the expression that supplies a row key into the source a sealed
    /// value will read it from.
    ///
    /// A literal is canonicalised now, because the statement text is all it
    /// depends on. A placeholder cannot be: its bytes arrive at Bind, so only
    /// the *index* and the type cross Parse→Bind. Anything else — a function
    /// call, a column reference, `DEFAULT` — is refused by the caller, because
    /// a row key the proxy cannot evaluate is a row it cannot name.
    pub(super) fn row_key_source(
        &self,
        expr: &Expr,
        spec: &ResolvedRowKey,
    ) -> Option<RowKeySource> {
        match unwrap_casts(expr) {
            Expr::Value(Value::Placeholder(placeholder)) => placeholder_index(placeholder)
                .map(|index| RowKeySource::Param { index, type_oid: spec.type_oid }),
            other => {
                // The literal's own text is what the server will store, so it
                // is canonicalised through the same type as the value that
                // comes back on read: `WHERE id = 0042` and a returned `42`
                // have to agree, or the row would not open.
                let text = literal_plaintext(other, WireForm::Text)?;
                rowkey::canonical(spec.type_oid, rowkey::Format::Text, Some(&text))
                    .ok()
                    .map(RowKeySource::Literal)
            }
        }
    }

    pub(super) fn rewrite_insert_values(
        &self,
        insert: &mut Insert,
        columns: &Columns,
        params: &mut ParamTransforms,
    ) -> Result<SealedValues, Rejection> {
        let protected: Vec<(usize, &Ident, Arc<dyn FieldTransform>)> = insert
            .columns
            .iter()
            .enumerate()
            .filter_map(|(position, ident)| {
                columns.get(&normalize(ident)).map(|transform| (position, ident, transform.clone()))
            })
            .collect();
        if protected.is_empty() {
            return Ok(SealedValues::default());
        }
        let table = insert.table_name.clone();
        let Some(source) = insert.source.as_mut() else { return Ok(SealedValues::default()) };
        let SetExpr::Values(values) = source.body.as_mut() else {
            self.unprotected(&Unprotected::InsertFromSelect(&table))?;
            return Ok(SealedValues::default());
        };
        // A row-bound table needs its key in the column list of every INSERT:
        // the value has to be sealed against the row it lands in, and a
        // server-generated key does not exist until after this statement runs.
        let Some((schema, table_name)) = resolved_name(&table) else {
            return Ok(SealedValues::default());
        };
        let spec = self.row_key_spec(&schema, &table_name);
        let key_position = spec.as_ref().and_then(|spec| {
            insert.columns.iter().position(|ident| normalize(ident) == spec.name.to_lowercase())
        });
        if let (Some(spec), None) = (spec.as_ref(), key_position) {
            self.unprotected(&Unprotected::RowKeyMissing {
                table: format!("{schema}.{table_name}"),
                column: spec.name.clone(),
                shape: "INSERT without the row key in its column list",
            })?;
            return Ok(SealedValues::default());
        }

        let mut sealed = SealedValues::default();
        for row in &mut values.rows {
            // Read before the mutable borrows below: every protected value in
            // this row binds to this row's key.
            let row_source = match (spec.as_ref(), key_position) {
                (Some(spec), Some(position)) => {
                    let Some(source) =
                        row.get(position).and_then(|expr| self.row_key_source(expr, spec))
                    else {
                        self.unprotected(&Unprotected::RowKeyMissing {
                            table: format!("{schema}.{table_name}"),
                            column: spec.name.clone(),
                            shape: "INSERT whose row key is not a literal or a parameter",
                        })?;
                        return Ok(SealedValues::default());
                    };
                    source
                }
                _ => RowKeySource::None,
            };
            for (position, ident, transform) in &protected {
                if let Some(expr) = row.get_mut(*position) {
                    let target = SealTarget { transform, column: &ident.value, row: &row_source };
                    sealed.changed |= self.seal_expr(expr, &target, params)?;
                }
            }
        }
        sealed.columns = protected.iter().map(|(_, ident, _)| normalize(ident)).collect();
        Ok(sealed)
    }

    /// Seals every assignment that targets a protected column. Shared by
    /// `UPDATE` and by `INSERT ... ON CONFLICT DO UPDATE`.
    pub(super) fn seal_assignments(
        &self,
        assignments: &mut [Assignment],
        target: &AssignmentScope<'_>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let mut changed = false;
        for Assignment { target: assigned, value } in assignments {
            match assigned {
                AssignmentTarget::ColumnName(column) => {
                    let Some(ident) = column.0.last() else { continue };
                    let name = normalize(ident);
                    let Some(transform) = target.columns.get(&name) else { continue };
                    if target.re_stores_a_sealed_value(value, &name) {
                        continue;
                    }
                    let transform = transform.clone();
                    let name = ident.value.clone();
                    let seal_target =
                        SealTarget { transform: &transform, column: &name, row: &target.row };
                    changed |= self.seal_expr(value, &seal_target, params)?;
                }
                AssignmentTarget::Tuple(names) => {
                    changed |= self.seal_tuple_assignment(names, value, target, params)?;
                }
            }
        }
        Ok(changed)
    }

    /// Seals the protected elements of a row-wise `SET (a, b) = (x, y)`.
    ///
    /// This shape used to fall out of [`Self::seal_assignments`] on a
    /// `continue`, which made it the one way to write plaintext into a
    /// protected column with *no* operator-visible signal at all: not sealed,
    /// not indexed, and never routed to [`Self::unprotected`], so even
    /// `on_unprotected = "reject"` relayed it. Everything here therefore either
    /// seals or signals; nothing returns quietly once a protected column is in
    /// the target list.
    ///
    /// The value side has more shapes than the syntax suggests, all confirmed
    /// against sqlparser 0.53:
    ///
    /// - `(a, b) = (x, y)` is an [`Expr::Tuple`], the ordinary case.
    /// - `(a) = (x)` is an [`Expr::Nested`] — a one-element parenthesised list
    ///   is indistinguishable from a grouping paren, so it never becomes a
    ///   tuple. Missing this would leave single-column row-wise assignment,
    ///   the easiest form to write, still bypassing the rewrite. It is read as
    ///   a one-element list whatever the target arity, so that `(a, b) = (x)`
    ///   is reported as the arity mismatch it is rather than as an
    ///   unrecognised expression shape.
    /// - `(a, b) = (SELECT ...)` is an [`Expr::Subquery`] and `(a, b) =
    ///   ROW(x, y)` an [`Expr::Function`]. Neither can be paired up
    ///   element-wise, so both are signalled rather than skipped.
    ///
    /// Arity is checked rather than zipped. `SET (a, b) = ('one')` parses
    /// cleanly even though Postgres rejects it at execution time, and pairing
    /// by the shorter side would seal `a` while silently leaving the statement
    /// mismatched.
    pub(super) fn seal_tuple_assignment(
        &self,
        names: &[ObjectName],
        value: &mut Expr,
        target: &AssignmentScope<'_>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        // Qualified targets are legal here (`SET (u.email, id) = ...`), so the
        // last ident names the column, as on the single-column path.
        let protected: Vec<(usize, &Ident, Arc<dyn FieldTransform>)> = names
            .iter()
            .enumerate()
            .filter_map(|(position, name)| {
                let ident = name.0.last()?;
                let transform = target.columns.get(&normalize(ident))?;
                Some((position, ident, transform.clone()))
            })
            .collect();
        if protected.is_empty() {
            return Ok(false);
        }

        // Signals every protected column in the target, so the operator sees
        // each one rather than only the first.
        let signal = |site: &dyn Fn(&str) -> Unprotected<'_>| -> Result<bool, Rejection> {
            for (_, ident, _) in &protected {
                self.unprotected(&site(&ident.value))?;
            }
            Ok(false)
        };

        let elements: &mut [Expr] = match value {
            Expr::Tuple(exprs) => exprs.as_mut_slice(),
            Expr::Nested(inner) => std::slice::from_mut(&mut **inner),
            other => {
                let shape = expr_shape(other);
                return signal(&|column| Unprotected::UnsupportedValue { column, shape });
            }
        };
        if elements.len() != names.len() {
            return signal(&|column| Unprotected::UnsupportedValue {
                column,
                shape: "row-wise assignment whose value list does not match the column list",
            });
        }

        let mut changed = false;
        for (position, ident, transform) in &protected {
            if target.re_stores_a_sealed_value(&elements[*position], &normalize(ident)) {
                continue;
            }
            let seal_target = SealTarget { transform, column: &ident.value, row: &target.row };
            changed |= self.seal_expr(&mut elements[*position], &seal_target, params)?;
        }
        Ok(changed)
    }
}
