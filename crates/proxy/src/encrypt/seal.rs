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
    Assignment, AssignmentTarget, ConflictTarget, Expr, Ident, Insert, ObjectName, SetExpr,
    TableFactor, TableWithJoins, UnaryOperator, Value,
};

use super::catalog::{normalize, resolved_name, Columns};
use super::frame::record_param;
use super::scope::{expr_shape, ScopedTable};
use super::{
    placeholder_index, text_plaintext, unwrap_casts, AssignmentRow, AssignmentScope, QueryRewriter,
    Rejection, SealTarget, SealedValues, Unprotected,
};
use crate::portal::{ParamAction, ParamTransforms, RowKeySource};
use crate::rows::ResolvedRowKey;
use crate::Error;
use dbsec_core::rowkey;

/// The parts of an `UPDATE` that decide which row its assignment list writes.
///
/// A struct rather than four more parameters: the repo caps a function at five
/// and these are only ever read together.
pub(super) struct UpdateTarget<'a> {
    /// The relation being written, with any joins sqlparser attached to it.
    pub(super) table: &'a TableWithJoins,
    /// `UPDATE ... FROM other`, which makes the statement a join.
    pub(super) from: Option<&'a TableWithJoins>,
    pub(super) selection: Option<&'a Expr>,
    pub(super) assignments: &'a [Assignment],
}

/// The configured row-key column name, as a SQL reference must fold to in order
/// to name it.
///
/// The catalog holds configured names *raw* and matches them against
/// [`normalize`], which folds an identifier the way PostgreSQL does: ASCII-only
/// downcasing for an unquoted name, no folding at all for a quoted one. So the
/// raw name is already the right side of the comparison, and folding it again
/// here would be wrong in both directions.
///
/// This used to be `spec.name.to_lowercase()`, which is Rust's *Unicode* case
/// folding and disagrees with the server twice over: a `row_key` of `Ämail`
/// became `ämail` while `normalize` leaves it `Ämail`, and a `row_key` of
/// `rowKey` became `rowkey` while the `"rowKey"` reference that
/// [`Config::validate`](crate::config::Config::validate) tells the operator to
/// use folds to `rowKey`. Either way a valid reference to the row key resolved
/// to nothing: refused under `reject`, and silently sealed cell-only under
/// `warn` — the protection quietly weaker than the configuration promises. The
/// same divergence on protected *column* names is what
/// [`dbsec_core::ident::fold_identifier`] was written for.
fn row_key_name(spec: &ResolvedRowKey) -> &str {
    &spec.name
}

/// Whether an assignment list writes `wanted`, on either target shape: `SET id
/// = …` and the row-wise `SET (id, ssn) = (…)`.
fn assigns_column(assignments: &[Assignment], wanted: &str) -> bool {
    let named = |name: &ObjectName| name.0.last().is_some_and(|ident| normalize(ident) == wanted);
    assignments.iter().any(|assignment| match &assignment.target {
        AssignmentTarget::ColumnName(name) => named(name),
        AssignmentTarget::Tuple(names) => names.iter().any(named),
    })
}

/// Whether `expr` names the row key **of the relation the statement writes**.
///
/// Matching the last ident alone answered a different question — "does this
/// spell the row key" — and `Statement::Update` carries a `FROM`, so `UPDATE
/// users u SET ssn = 'x' FROM audit a WHERE a.id = 1 AND u.id = 99` matched
/// `a.id` first and sealed `ssn` against row `1` while the server wrote row
/// `99`. The value lands in a row it is not bound to and surfaces at read time
/// as a false tamper alarm that kills the session — and the joined relation
/// and its predicate are the part of such a statement an attacker has the most
/// freedom to shape.
///
/// A qualifier is therefore resolved against the target relation, and a bare
/// name is accepted only when the statement joins nothing else: the catalog
/// holds the columns of protected tables only, so with a join in play the
/// proxy cannot prove a bare `id` is not the other side's.
fn names_row_key(expr: &Expr, wanted: &str, target: &ScopedTable<'_>, joined: bool) -> bool {
    match expr {
        Expr::Identifier(ident) => !joined && normalize(ident) == wanted,
        Expr::CompoundIdentifier(idents) => match idents.split_last() {
            Some((column, qualifiers)) => normalize(column) == wanted && target.matches(qualifiers),
            None => false,
        },
        _ => false,
    }
}

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
    fn row_key_in_predicate(
        &self,
        expr: &Expr,
        spec: &ResolvedRowKey,
        target: &ScopedTable<'_>,
        joined: bool,
    ) -> Option<RowKeySource> {
        use sqlparser::ast::BinaryOperator;
        match expr {
            Expr::BinaryOp { left, op: BinaryOperator::And, right } => self
                .row_key_in_predicate(left, spec, target, joined)
                .or_else(|| self.row_key_in_predicate(right, spec, target, joined)),
            Expr::Nested(inner) => self.row_key_in_predicate(inner, spec, target, joined),
            Expr::BinaryOp { left, op: BinaryOperator::Eq, right } => {
                let wanted = row_key_name(spec);
                let names = |e: &Expr| names_row_key(e, wanted, target, joined);
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

    /// Which row an `UPDATE`'s assignment list writes.
    ///
    /// Nothing is reported here: whether a gap matters depends on what the list
    /// turns out to assign, which only [`Self::seal_assignments`] knows. See
    /// [`AssignmentRow`].
    pub(super) fn update_row(&self, target: &UpdateTarget<'_>, columns: &Columns) -> AssignmentRow {
        let TableFactor::Table { name, alias, .. } = &target.table.relation else {
            return AssignmentRow::Known(RowKeySource::None);
        };
        let Some((schema, table_name)) = resolved_name(name) else {
            return AssignmentRow::Known(RowKeySource::None);
        };
        let Some(spec) = self.row_key_spec(&schema, &table_name) else {
            return AssignmentRow::Known(RowKeySource::None);
        };
        let qualified = format!("{schema}.{table_name}");
        let wanted = row_key_name(&spec);
        if assigns_column(target.assignments, wanted) {
            return AssignmentRow::Reassigned { table: qualified, column: spec.name };
        }
        let scoped = ScopedTable {
            alias: alias.as_ref().map(|alias| normalize(&alias.name)),
            name: name.0.iter().map(normalize).collect(),
            columns: std::borrow::Cow::Borrowed(columns),
            // Only the write direction is consulted below — this scope exists
            // to find the row key in a predicate — but a `ScopedTable` carries
            // both, so the read direction is filled in from the same name.
            read_columns: std::borrow::Cow::Borrowed(self.catalog.read_columns_of(name)),
        };
        let joined = target.from.is_some() || !target.table.joins.is_empty();
        let found = target
            .selection
            .and_then(|where_| self.row_key_in_predicate(where_, &spec, &scoped, joined));
        match found {
            Some(source) => AssignmentRow::Known(source),
            None => AssignmentRow::Missing {
                table: qualified,
                column: spec.name,
                shape: "UPDATE whose WHERE does not pin one row by its row key",
            },
        }
    }

    /// Which row an `INSERT`'s conflict action writes.
    ///
    /// The conflict action updates the row that *already exists*, so its key is
    /// the one the `VALUES` row proposed only when the conflict is on the row
    /// key itself: `ON CONFLICT (id)` means the row that conflicted is the row
    /// with that `id`. `ON CONFLICT (email)` conflicts on some other unique
    /// column, whose row may carry any key at all, and MySQL's `ON DUPLICATE
    /// KEY UPDATE` names no key — both are gaps, not derivations.
    pub(super) fn conflict_row(
        &self,
        insert: &Insert,
        conflict_target: Option<&ConflictTarget>,
        assignments: &[Assignment],
    ) -> AssignmentRow {
        let Some((schema, table_name)) = resolved_name(&insert.table_name) else {
            return AssignmentRow::Known(RowKeySource::None);
        };
        let Some(spec) = self.row_key_spec(&schema, &table_name) else {
            return AssignmentRow::Known(RowKeySource::None);
        };
        let qualified = format!("{schema}.{table_name}");
        let wanted = row_key_name(&spec);
        if assigns_column(assignments, wanted) {
            return AssignmentRow::Reassigned { table: qualified, column: spec.name };
        }
        let missing = |shape| AssignmentRow::Missing {
            table: qualified.clone(),
            column: spec.name.clone(),
            shape,
        };
        match conflict_target {
            Some(ConflictTarget::Columns(columns))
                if columns.iter().any(|ident| normalize(ident) == wanted) => {}
            _ => return missing("conflict action whose ON CONFLICT target is not the row key"),
        }
        let Some(position) = insert.columns.iter().position(|ident| normalize(ident) == wanted)
        else {
            return missing("conflict action of an INSERT without the row key in its column list");
        };
        let Some(source) = insert.source.as_ref() else {
            return missing("conflict action of an INSERT with no VALUES list");
        };
        let SetExpr::Values(values) = source.body.as_ref() else {
            return missing("conflict action of an INSERT ... SELECT");
        };
        // One conflict action, one sealed value: a multi-row VALUES list
        // conflicts once per row and each conflicting row carries its own key,
        // so there is no single key the action's values could bind to.
        let [row] = values.rows.as_slice() else {
            return missing("conflict action of a multi-row INSERT");
        };
        match row.get(position).and_then(|expr| self.row_key_source(expr, &spec)) {
            Some(source) => AssignmentRow::Known(source),
            None => missing("conflict action whose row key is not a literal or a parameter"),
        }
    }

    /// The row a protected assignment seals against, reporting the site when
    /// the statement gives none.
    ///
    /// Under `reject` the report is the answer and nothing is written. Under
    /// `warn` the value still seals, cell-only — the binding this table had
    /// before it declared a row key. Falling back to *no* sealing would be a
    /// downgrade dressed as a fix: it turns a relocatable ciphertext into
    /// plaintext at rest, which is the one outcome `warn` exists to avoid.
    fn row_of(&self, row: &AssignmentRow) -> Result<RowKeySource, Rejection> {
        match row {
            AssignmentRow::Known(source) => Ok(source.clone()),
            AssignmentRow::Missing { table, column, shape } => {
                self.row_key_missing(table, column, shape)?;
                Ok(RowKeySource::None)
            }
            AssignmentRow::Reassigned { table, column } => {
                self.unprotected(&Unprotected::RowKeyReassigned {
                    table: table.clone(),
                    column: column.clone(),
                })?;
                Ok(RowKeySource::None)
            }
        }
    }

    /// Reports a statement that writes a row-bound table without saying which
    /// row it writes.
    ///
    /// The one place [`Unprotected::RowKeyMissing`] is built. The three sites
    /// that reach it — an `INSERT` without the key in its column list, an
    /// `INSERT` whose key is neither a literal nor a parameter, and an
    /// assignment list whose row the statement never pinned — differ only in
    /// `shape`, so the identification of the table (`schema.table`, then the
    /// key column) belongs here rather than being re-derived at each one.
    ///
    /// Like every other [`Unprotected`] site this consults `on_unprotected`:
    /// under `warn` it logs and the value seals cell-only, under `reject` it
    /// refuses the statement.
    fn row_key_missing(
        &self,
        table: &str,
        column: &str,
        shape: &'static str,
    ) -> Result<(), Rejection> {
        self.unprotected(&Unprotected::RowKeyMissing {
            table: table.to_owned(),
            column: column.to_owned(),
            shape,
        })
    }

    /// The declared row key for a table, if it has one.
    ///
    /// `None` covers both "no `[[table]]` entry" and "no read context", and
    /// both mean cell-only binding — the behaviour before row keys existed.
    fn row_key_spec(&self, schema: &str, table: &str) -> Option<ResolvedRowKey> {
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
    fn row_key_source(&self, expr: &Expr, spec: &ResolvedRowKey) -> Option<RowKeySource> {
        match unwrap_casts(expr) {
            Expr::Value(Value::Placeholder(placeholder)) => {
                placeholder_index(placeholder).map(|index| RowKeySource::Param {
                    index,
                    type_oid: spec.type_oid,
                    column: Arc::from(spec.name.as_str()),
                })
            }
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
        let qualified = format!("{schema}.{table_name}");
        let spec = self.row_key_spec(&schema, &table_name);
        let key_position = spec.as_ref().and_then(|spec| {
            let wanted = row_key_name(spec);
            insert.columns.iter().position(|ident| normalize(ident) == wanted)
        });
        // Reported, then sealed cell-only — never returned unsealed. See
        // [`Self::row_of`] for why `warn` falls back to the weaker binding
        // rather than to none at all.
        if let (Some(spec), None) = (spec.as_ref(), key_position) {
            self.row_key_missing(
                &qualified,
                &spec.name,
                "INSERT without the row key in its column list",
            )?;
        }

        let mut sealed = SealedValues::default();
        // One report per statement, not per row: a multi-row VALUES list whose
        // rows are all unnamed describes one gap, and a thousand-row INSERT
        // should not write a thousand warnings about it.
        let mut reported = false;
        for row in &mut values.rows {
            // Read before the mutable borrows below: every protected value in
            // this row binds to this row's key.
            let row_source = match (spec.as_ref(), key_position) {
                (Some(spec), Some(position)) => {
                    match row.get(position).and_then(|expr| self.row_key_source(expr, spec)) {
                        Some(source) => source,
                        None => {
                            if !std::mem::replace(&mut reported, true) {
                                self.row_key_missing(
                                    &qualified,
                                    &spec.name,
                                    "INSERT whose row key is not a literal or a parameter",
                                )?;
                            }
                            RowKeySource::None
                        }
                    }
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
                    // Before the `EXCLUDED` whitelist, not after: what that
                    // whitelist re-stores is a value sealed against the
                    // *inserted* row's key, so it is only the right bytes for
                    // the conflicting row when the two rows share a key —
                    // which is exactly what a `Known` row here means.
                    let row = self.row_of(&target.row)?;
                    if target.re_stores_a_sealed_value(value, &name) {
                        continue;
                    }
                    let transform = transform.clone();
                    let name = ident.value.clone();
                    let seal_target =
                        SealTarget { transform: &transform, column: &name, row: &row };
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
    fn seal_tuple_assignment(
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
            let row = self.row_of(&target.row)?;
            if target.re_stores_a_sealed_value(&elements[*position], &normalize(ident)) {
                continue;
            }
            let seal_target = SealTarget { transform, column: &ident.value, row: &row };
            changed |= self.seal_expr(&mut elements[*position], &seal_target, params)?;
        }
        Ok(changed)
    }

    /// Seals one literal in place, or records the placeholder for Bind time.
    /// Returns whether the statement text changed.
    fn seal_expr(
        &self,
        expr: &mut Expr,
        target: &SealTarget<'_>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let SealTarget { transform, column, row } = target;
        match unwrap_casts(expr) {
            Expr::Value(Value::Placeholder(placeholder)) => {
                if let Some(index) = placeholder_index(placeholder) {
                    record_param(
                        params,
                        index,
                        ParamAction::Seal { transform: (*transform).clone(), row: (*row).clone() },
                    )?;
                }
                return Ok(false);
            }
            Expr::Value(Value::Null) => return Ok(false),
            _ => {}
        }
        if !self.literal_agrees_with_server(expr) {
            self.unprotected(&Unprotected::AmbiguousLiteral { column })?;
            return Ok(false);
        }
        let Some(plaintext) = literal_plaintext(expr, transform.wire()) else {
            self.unprotected(&Unprotected::UnsupportedValue { column, shape: expr_shape(expr) })?;
            return Ok(false);
        };
        // The literal's row key is known now — it came out of the same
        // statement — so unlike a placeholder there is nothing to defer.
        let row_key = match row {
            RowKeySource::Literal(key) => Some(key.clone()),
            // A literal value in a row whose *key* is a parameter cannot be
            // sealed here: the key does not exist until Bind, and this value
            // is being written now. Refused rather than sealed unbound.
            RowKeySource::Param { .. } => {
                self.unprotected(&Unprotected::UnsupportedValue {
                    column,
                    shape: "literal in a row whose key is a bound parameter",
                })?;
                return Ok(false);
            }
            RowKeySource::None => None,
        };
        let sealed = transform.seal(&plaintext, row_key.as_ref()).map_err(Error::Wire)?;
        *expr = match transform.wire() {
            WireForm::Bytea => bytea_literal(&sealed),
            // FPE digits and HMAC hex carry no backslash, so an ordinary
            // literal denotes the same string under either setting of
            // `standard_conforming_strings`.
            WireForm::Text => Expr::Value(Value::SingleQuotedString(
                String::from_utf8_lossy(&sealed).into_owned(),
            )),
        };
        Ok(true)
    }
}

/// A BYTEA value as SQL text: `E'\\x…'`, PostgreSQL's hex input syntax inside
/// an *escape* string literal.
///
/// The plain `'\x…'` spelling reads as hex bytea only while
/// `standard_conforming_strings` is on — with it off, the server applies
/// C-style backslash processing to the literal first and every sealed write
/// and every blind-index match is silently corrupted. `E'…'` processes
/// backslashes whatever that setting says, so doubling the one backslash here
/// makes the literal mean the same thing either way. sqlparser renders the
/// stored `\x…` back out with the backslash doubled, and reads it back to
/// `\x…` when the rewritten text is re-parsed for validation.
pub(super) fn bytea_literal(value: &[u8]) -> Expr {
    Expr::Value(Value::EscapedStringLiteral(format!("\\x{}", hex::encode(value))))
}

/// The plaintext a literal expression stands for, or `None` when it is not a
/// literal at all. For BYTEA-form columns a `\x`-prefixed string is
/// Postgres' hex input syntax, so it denotes the bytes it encodes rather than
/// its own characters — sealing it verbatim would round-trip the hex text.
///
/// Every string-literal syntax Postgres accepts is matched, not just the
/// ordinary `'...'` one. Missing any of them is a fail-open under the default
/// `on_unprotected = "warn"`: the literal falls through to the
/// [`Unprotected::UnsupportedValue`] gate, which under `warn` forwards the
/// statement verbatim and lets the server store the plaintext. `E'...'` is the
/// one that matters most in practice — many drivers emit it automatically for
/// any string containing a backslash, so it needs no unusual client to reach.
///
/// Each variant carries content sqlparser has already *decoded*, which is what
/// makes one shared handler correct: `E'o\'brien'` arrives as `o'brien` and
/// `U&'d\0061t\+000061'` as `data`, so the bytes sealed are the bytes the
/// server would have stored. `U&'...' UESCAPE '!'` is the sole gap and it does
/// not reach here at all — sqlparser 0.53 cannot parse it, so it is caught
/// earlier as [`Unprotected::Unparseable`] rather than silently mis-sealed.
pub(super) fn literal_plaintext(expr: &Expr, wire: WireForm) -> Option<Vec<u8>> {
    match unwrap_casts(expr) {
        Expr::Value(
            Value::SingleQuotedString(s)
            | Value::EscapedStringLiteral(s)
            | Value::UnicodeStringLiteral(s)
            | Value::NationalStringLiteral(s),
        ) => Some(text_plaintext(s, wire)),
        Expr::Value(Value::DollarQuotedString(s)) => Some(text_plaintext(&s.value, wire)),
        Expr::Value(Value::Number(n, _)) => Some(n.as_bytes().to_vec()),
        // A signed number is a `UnaryOp` over a `Number`, never a `Number` with
        // the sign inside it. Missing that made `WHERE id = -1` name no row key
        // at all, so a row with an ordinary negative key fell through to the
        // `RowKeyMissing` gate and sealed cell-only under `warn` (SEC-11).
        Expr::UnaryOp { op: UnaryOperator::Minus, expr } => match unwrap_casts(expr) {
            Expr::Value(Value::Number(n, _)) => Some(format!("-{n}").into_bytes()),
            _ => None,
        },
        Expr::UnaryOp { op: UnaryOperator::Plus, expr } => match unwrap_casts(expr) {
            Expr::Value(Value::Number(n, _)) => Some(n.as_bytes().to_vec()),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::sync::Arc;

    use dbsec_core::blind_index;
    use dbsec_core::transform::FieldTransform;
    use dbsec_pgwire as pgwire;

    use crate::config::OnUnprotected;
    use crate::encrypt::test_support::*;
    use crate::encrypt::WriteCatalog;
    use crate::rows::tests::transform;
    use crate::session::FrameAction;

    #[test]
    fn insert_literal_is_sealed() {
        let mut rewriter = rewriter(catalog(false));
        let sql = rewritten_query(
            &mut rewriter,
            "INSERT INTO users (id, email) VALUES (1, 'alice@example.com')",
        )
        .expect("rewritten");
        assert!(!sql.contains("alice@example.com"));
        assert_eq!(open_hex_literal(&sql, false), b"alice@example.com");
    }

    #[test]
    fn update_literal_is_sealed_and_searchable_gets_index() {
        let mut rewriter = rewriter(catalog(true));
        let sql = rewritten_query(
            &mut rewriter,
            "UPDATE users SET email = 'bob@example.com' WHERE id = 7",
        )
        .expect("rewritten");
        assert!(!sql.contains("bob@example.com"));
        assert_eq!(open_hex_literal(&sql, true), b"bob@example.com");

        // The stored form carries the blind index.
        let stored = hex::decode(sealed_hex(&sql).unwrap()).unwrap();
        let (index, _) = blind_index::split(&stored).unwrap();
        assert_eq!(index, blind_index::compute(&crate::rows::tests::INDEX_KEY, b"bob@example.com"));
    }

    /// psycopg (client-side binding, and psycopg2 always) renders a bytes
    /// parameter as `'\x…'::bytea`: the cast has to be seen through, and the
    /// hex decoded, or the column would store the hex text — or plaintext.
    #[test]
    fn cast_wrapped_bytea_literals_are_sealed_as_the_bytes_they_denote() {
        let mut rewriter = rewriter(catalog(false));
        let hex = hex::encode("alice@example.com");
        let sql = rewritten_query(
            &mut rewriter,
            &format!("INSERT INTO users (email) VALUES ('\\x{hex}'::bytea)"),
        )
        .expect("rewritten");
        assert!(!sql.contains(&hex), "the plaintext bytes are still on the wire: {sql}");
        assert_eq!(open_hex_literal(&sql, false), b"alice@example.com");
    }

    /// Postgres has five string-literal syntaxes and only one of them is
    /// `'...'`. Each of the others reached the `UnsupportedValue` gate, which
    /// under the default `warn` forwards the statement verbatim — so the
    /// server decoded the literal and stored the plaintext in a column the
    /// operator had marked protected.
    ///
    /// Each case asserts on the *decoded* content, which is the part that
    /// makes this more than a variant list: `E'o\'brien'` must seal
    /// `o'brien`, not the source text, or the column would round-trip a
    /// backslash the client never sent.
    #[test]
    fn every_postgres_string_literal_syntax_is_sealed() {
        for (literal, plaintext) in [
            (r"E'o\'brien@secret.test'", "o'brien@secret.test"),
            (r"E'tab\there@secret.test'", "tab\there@secret.test"),
            ("$$alice@secret.test$$", "alice@secret.test"),
            ("$tag$bob@secret.test$tag$", "bob@secret.test"),
            (r"U&'d\0061ve@secret.test'", "dave@secret.test"),
            ("N'nina@secret.test'", "nina@secret.test"),
        ] {
            let mut rewriter = rewriter(catalog(false));
            let sql = rewritten_query(
                &mut rewriter,
                &format!("INSERT INTO users (id, email) VALUES (1, {literal})"),
            )
            .unwrap_or_else(|| panic!("{literal} was not rewritten at all"));

            assert!(!sql.contains("secret.test"), "{literal} left plaintext on the wire: {sql}");
            assert_eq!(
                open_hex_literal(&sql, false),
                plaintext.as_bytes(),
                "{literal} sealed the wrong bytes"
            );
        }
    }

    /// `E'\\x41'` decodes to the four characters `\x41`, which for a BYTEA
    /// column is Postgres' hex input syntax for one byte. The decode and the
    /// hex read have to compose in that order, or the column stores the
    /// literal text instead of the byte it denotes.
    #[test]
    fn an_escape_string_holding_bytea_hex_syntax_seals_the_bytes_it_denotes() {
        let mut rewriter = rewriter(catalog(false));
        let hex = hex::encode("alice@secret.test");
        let sql = rewritten_query(
            &mut rewriter,
            &format!(r"INSERT INTO users (email) VALUES (E'\\x{hex}')"),
        )
        .expect("rewritten");
        assert!(!sql.contains(&hex), "the plaintext bytes are still on the wire: {sql}");
        assert_eq!(open_hex_literal(&sql, false), b"alice@secret.test");
    }

    #[test]
    fn text_shaped_transforms_seal_as_plain_literals_and_params() {
        use crate::rows::tests::OneKey;
        use dbsec_core::transform::{FpeTransform, TokenTransform};

        let fpe: Arc<dyn FieldTransform> =
            Arc::new(FpeTransform::new(Arc::new(OneKey), "public.users.phone".into(), true));
        let token: Arc<dyn FieldTransform> =
            Arc::new(TokenTransform::new(Arc::new(OneKey), "public.users.ssn".into()));
        let catalog = Arc::new(WriteCatalog::new(
            &[column("phone", fpe.clone(), false), column("ssn", token.clone(), false)],
            OnUnprotected::Warn,
        ));
        let mut rewriter = rewriter(catalog);

        // FPE literal keeps its digit shape — no \x hex, no plaintext.
        let sql = rewritten_query(
            &mut rewriter,
            "INSERT INTO users (phone, ssn) VALUES ('555-867-5309', 'abc')",
        )
        .expect("rewritten");
        assert!(!sql.contains("555-867-5309") && !sql.contains("\\x"), "{sql}");
        let pseudonym = sql.split('\'').nth(1).expect("first literal");
        assert_eq!(pseudonym.len(), 12);
        assert_eq!(&pseudonym[3..4], "-");
        assert_eq!(fpe.open(pseudonym.as_bytes(), None).unwrap().unwrap(), b"555-867-5309");
        // Token literal is the 64-char hex HMAC.
        let token_literal = sql.split('\'').nth(3).expect("second literal");
        assert_eq!(token_literal.len(), 64);
        assert_eq!(token_literal.as_bytes(), token.seal(b"abc", None).unwrap().as_slice());

        // Bound text-format param for an FPE column stays digit-shaped.
        let parse = pgwire::encode_parse(
            b"s1",
            b"UPDATE users SET phone = $1 WHERE id = $2",
            &0i16.to_be_bytes(),
        );
        assert!(matches!(rewriter.on_frame(b'P', &parse).unwrap(), FrameAction::Relay));
        let bind = pgwire::encode_bind(
            b"",
            b"s1",
            &[],
            &[
                Some(Cow::Borrowed(b"555-867-5309".as_slice())),
                Some(Cow::Borrowed(b"7".as_slice())),
            ],
            &0i16.to_be_bytes(),
        )
        .unwrap();
        let FrameAction::Replace(rewritten) = rewriter.on_frame(b'B', &bind).unwrap() else {
            panic!("bind not rewritten")
        };
        let bound = pgwire::parse_bind(&rewritten).unwrap();
        let sealed = bound.params[0].unwrap();
        assert!(!sealed.starts_with(b"\\x"));
        assert_eq!(fpe.open(sealed, None).unwrap().unwrap(), b"555-867-5309");
        assert_eq!(bound.params[1], Some(b"7".as_slice()));
    }

    #[test]
    fn fpe_seal_of_tiny_domain_fails_closed() {
        use crate::rows::tests::OneKey;
        use dbsec_core::transform::FpeTransform;

        let fpe: Arc<dyn FieldTransform> =
            Arc::new(FpeTransform::new(Arc::new(OneKey), "public.users.pin".into(), true));
        let catalog =
            Arc::new(WriteCatalog::new(&[column("pin", fpe, false)], OnUnprotected::Warn));
        let mut rewriter = rewriter(catalog);
        let body = query_frame("INSERT INTO users (pin) VALUES ('1234')");
        assert!(rewriter.on_frame(b'Q', &body).is_err());
    }

    /// An `INSERT` into a row-bound table that cannot say which row it writes
    /// is a gap in the *binding*, not a licence to store plaintext. Under
    /// `warn` both such sites seal cell-only — a `DBS2` envelope, the binding
    /// the table had before it declared a row key — so adopting `row_key`
    /// never makes a statement less protected than it was.
    #[test]
    fn an_insert_that_cannot_name_its_row_seals_cell_only_under_warn() {
        use dbsec_core::envelope::{MAGIC, MAGIC_V3};

        // Both shapes: the key absent from the column list, and a key whose
        // value is neither a literal nor a parameter.
        for sql in [
            "INSERT INTO users (email) VALUES ('alice@secret.test')",
            "INSERT INTO users (id, email) VALUES (nextval('users_id_seq'), 'alice@secret.test')",
        ] {
            let mut rewriter = row_bound_rewriter();
            let rewritten = rewritten_query(&mut rewriter, sql).expect("rewritten");
            assert!(!rewritten.contains("alice@secret.test"), "plaintext left on the wire: {sql}");

            let stored = hex::decode(sealed_hex(&rewritten).expect("a sealed literal")).unwrap();
            let (_, envelope) = blind_index::split(&stored).expect("searchable column");
            assert!(
                envelope.starts_with(MAGIC),
                "{sql} did not seal cell-only: {:?}",
                &envelope[..4.min(envelope.len())]
            );
            assert_eq!(open_hex_literal(&rewritten, true), b"alice@secret.test");
        }

        // The contrast, so the fallback cannot silently become the only path:
        // when the statement does name its row, the value is row-bound.
        let mut rewriter = row_bound_rewriter();
        let rewritten = rewritten_query(
            &mut rewriter,
            "INSERT INTO users (id, email) VALUES (7, 'alice@secret.test')",
        )
        .expect("rewritten");
        let stored = hex::decode(sealed_hex(&rewritten).expect("a sealed literal")).unwrap();
        let (_, envelope) = blind_index::split(&stored).expect("searchable column");
        assert!(envelope.starts_with(MAGIC_V3), "a named row should seal row-bound");
    }

    /// Row-wise `SET (a, b) = (x, y)` is standard Postgres and parses to its
    /// own `AssignmentTarget::Tuple`, which the assignment loop used to drop on
    /// a `continue`. The single-element form is covered too: it parses as a
    /// grouping paren rather than a tuple, so it takes a different arm.
    #[test]
    fn row_wise_tuple_assignment_is_sealed() {
        for sql in [
            "UPDATE users SET (email, id) = ('alice@secret.test', 5)",
            "UPDATE users SET (id, email) = (5, 'alice@secret.test')",
            "UPDATE users SET (email) = ('alice@secret.test')",
            "UPDATE users SET (u.email, id) = ('alice@secret.test', 5)",
        ] {
            let mut rewriter = rewriter(catalog(false));
            let rewritten = rewritten_query(&mut rewriter, sql)
                .unwrap_or_else(|| panic!("not rewritten at all: {sql}"));
            assert!(!rewritten.contains("alice@secret.test"), "plaintext on the wire: {rewritten}");
            assert_eq!(open_hex_literal(&rewritten, false), b"alice@secret.test", "{sql}");
        }
    }

    #[test]
    fn row_wise_tuple_assignment_gets_the_blind_index_when_searchable() {
        let mut rewriter = rewriter(catalog(true));
        let sql =
            rewritten_query(&mut rewriter, "UPDATE users SET (email, id) = ('bob@secret.test', 5)")
                .expect("rewritten");
        assert_eq!(open_hex_literal(&sql, true), b"bob@secret.test");

        let stored = hex::decode(sealed_hex(&sql).unwrap()).unwrap();
        let (index, _) = blind_index::split(&stored).unwrap();
        assert_eq!(index, blind_index::compute(&crate::rows::tests::INDEX_KEY, b"bob@secret.test"));
    }

    /// `seal_assignments` is shared, so the upsert action takes the same path.
    #[test]
    fn row_wise_tuple_assignment_in_on_conflict_is_sealed() {
        let mut rewriter = rewriter(catalog(false));
        let sql = rewritten_query(
            &mut rewriter,
            "INSERT INTO users (id, email) VALUES (1, 'carol@secret.test') \
             ON CONFLICT (id) DO UPDATE SET (email, id) = ('dave@secret.test', 5)",
        )
        .expect("rewritten");
        assert!(!sql.contains("carol@secret.test"), "the inserted value leaked: {sql}");
        assert!(!sql.contains("dave@secret.test"), "the upsert value leaked: {sql}");
        assert_eq!(sql.matches(SEALED_PREFIX).count(), 2, "both values sealed: {sql}");
    }

    /// A tuple whose value side cannot be paired element-wise. Each of these
    /// is valid enough to parse, so without an explicit signal it would fall
    /// through to a plaintext write with nothing in the log.
    #[test]
    fn unpairable_tuple_assignment_is_a_site_and_is_refused() {
        for (sql, expected) in [
            ("UPDATE users SET (email, id) = (SELECT a, b FROM other)", "subquery"),
            ("UPDATE users SET (email, id) = ROW('alice@secret.test', 5)", "function call"),
            // Both parse cleanly; Postgres rejects them at execution time.
            // Pairing by the shorter side would have sealed `email` regardless.
            ("UPDATE users SET (email, id) = ('only-one')", "does not match the column list"),
            (
                "UPDATE users SET (email) = ('alice@secret.test', 5)",
                "does not match the column list",
            ),
        ] {
            let mut strict = rewriter(strict_catalog(false));
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            let refusal = refusal(&action);
            assert!(refusal.contains(expected), "{sql}\n  refusal was: {refusal}");
            assert!(!refusal.contains("secret.test"), "the refusal leaked plaintext: {refusal}");
        }
    }

    /// A tuple target naming no protected column is left exactly alone — the
    /// new arm must not turn ordinary row-wise updates into refusals.
    #[test]
    fn tuple_assignment_over_unprotected_columns_is_untouched() {
        let mut strict = rewriter(strict_catalog(false));
        let action = strict
            .on_frame(b'Q', &query_frame("UPDATE users SET (id, name) = (5, 'nobody')"))
            .unwrap();
        assert!(matches!(action, FrameAction::Relay), "relayed untouched");
    }

    /// The invariant this finding broke, stated directly: under *either*
    /// policy the plaintext must not reach the backend. `warn` seals it and
    /// relays the rewrite; `reject` answers the client instead. Before the
    /// fix `warn` relayed the plaintext verbatim and `reject` did too, because
    /// the statement never reached the reject decision.
    #[test]
    fn a_tuple_assignment_never_puts_plaintext_on_the_backend_wire() {
        let sql = "UPDATE users SET (email, id) = ('alice@secret.test', 5)";

        let mut warn = rewriter(catalog(false));
        match warn.on_frame(b'Q', &query_frame(sql)).unwrap() {
            FrameAction::Replace(body) => {
                let text = String::from_utf8_lossy(&body).into_owned();
                assert!(!text.contains("alice@secret.test"), "warn relayed plaintext: {text}");
            }
            other => panic!("warn must rewrite and relay, got {other:?}"),
        }

        let mut strict = rewriter(strict_catalog(false));
        match strict.on_frame(b'Q', &query_frame(sql)).unwrap() {
            // Sealing succeeds under reject too — there is nothing to refuse.
            FrameAction::Replace(body) => {
                let text = String::from_utf8_lossy(&body).into_owned();
                assert!(!text.contains("alice@secret.test"), "reject relayed plaintext: {text}");
            }
            FrameAction::Reply(bytes) => {
                assert_eq!(bytes[0], b'E');
                let text = String::from_utf8_lossy(&bytes).into_owned();
                assert!(!text.contains("alice@secret.test"), "the refusal leaked: {text}");
            }
            other => panic!("plaintext would reach the backend: {other:?}"),
        }
    }

    #[test]
    fn on_conflict_do_update_seals_protected_assignments() {
        let mut rewriter = rewriter(catalog(false));
        let sql = rewritten_query(
            &mut rewriter,
            "INSERT INTO users (id, email) VALUES (1, 'a@b.io') \
             ON CONFLICT (id) DO UPDATE SET email = 'c@d.io'",
        )
        .expect("rewritten");
        assert!(!sql.contains("a@b.io") && !sql.contains("c@d.io"), "{sql}");
        assert_eq!(sql.matches(SEALED_PREFIX).count(), 2, "both values sealed: {sql}");

        // A bound placeholder in the conflict action is sealed at Bind time.
        let parse = pgwire::encode_parse(
            b"up",
            b"INSERT INTO users (id, email) VALUES ($1, $2) \
              ON CONFLICT (id) DO UPDATE SET email = $3",
            &0i16.to_be_bytes(),
        );
        assert!(matches!(rewriter.on_frame(b'P', &parse).unwrap(), FrameAction::Relay));
        let bind = pgwire::encode_bind(
            b"",
            b"up",
            &[],
            &[
                Some(Cow::Borrowed(b"1".as_slice())),
                Some(Cow::Borrowed(b"a@b.io".as_slice())),
                Some(Cow::Borrowed(b"c@d.io".as_slice())),
            ],
            &0i16.to_be_bytes(),
        )
        .unwrap();
        let FrameAction::Replace(rewritten) = rewriter.on_frame(b'B', &bind).unwrap() else {
            panic!("bind not rewritten")
        };
        let bound = pgwire::parse_bind(&rewritten).unwrap();
        for (index, expected) in [(1, b"a@b.io".as_slice()), (2, b"c@d.io".as_slice())] {
            let stored =
                hex::decode(bound.params[index].unwrap().strip_prefix(b"\\x").unwrap()).unwrap();
            assert_eq!(transform(false).open(&stored, None).unwrap().unwrap(), expected);
        }
    }

    /// The conflict action carries a `WHERE` of its own, and it is a predicate
    /// over the target table exactly like an UPDATE's. Dropping it left a
    /// searchable equality there comparing plaintext against the stored
    /// `blind_index || envelope`: no rewrite, no signal, no rows.
    #[test]
    fn a_searchable_predicate_in_a_do_update_where_is_rewritten_or_signalled() {
        let mut qualified = rewriter(catalog(true));
        let sql = rewritten_query(
            &mut qualified,
            "INSERT INTO users (id) VALUES (1) \
             ON CONFLICT (id) DO UPDATE SET id = 2 WHERE users.email = 'a@b.io'",
        )
        .expect("rewritten");
        assert!(!sql.contains("a@b.io"), "{sql}");
        assert!(sql.contains("FROM 1 FOR 32"), "{sql}");

        // The alias an `INSERT INTO t AS x` gives the target is the only name
        // its conflict-action predicate can qualify with.
        let mut aliased = rewriter(catalog(true));
        let sql = rewritten_query(
            &mut aliased,
            "INSERT INTO users AS u (id) VALUES (1) \
             ON CONFLICT (id) DO UPDATE SET id = 2 WHERE u.email = 'a@b.io'",
        )
        .expect("rewritten");
        assert!(!sql.contains("a@b.io") && sql.contains("FROM 1 FOR 32"), "{sql}");

        // And a shape no index can answer is a gate, not a silent relay.
        let mut strict = rewriter(strict_catalog(true));
        let action = strict
            .on_frame(
                b'Q',
                &query_frame(
                    "INSERT INTO users (id) VALUES (1) \
                     ON CONFLICT (id) DO UPDATE SET id = 2 WHERE email LIKE 'a%'",
                ),
            )
            .unwrap();
        assert!(refusal(&action).contains("searchable column email"));
    }

    /// `SET col = EXCLUDED.col` re-stores the value this proxy sealed in the
    /// same statement's VALUES list, so it is neither sealed again nor
    /// refused — refusing the canonical upsert is what keeps operators off
    /// `reject`. The whitelist stops there: every reference that is not
    /// provably already sealed is still a site.
    #[test]
    fn the_canonical_upsert_re_stores_the_value_it_just_sealed() {
        let sql = "INSERT INTO users (id, email) VALUES (1, 'a@b.io') \
                   ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email";

        let mut permissive = rewriter(catalog(false));
        let rewritten = rewritten_query(&mut permissive, sql).expect("rewritten");
        assert!(!rewritten.contains("a@b.io"), "{rewritten}");
        assert_eq!(
            rewritten.matches(SEALED_PREFIX).count(),
            1,
            "only the VALUES literal: {rewritten}"
        );
        assert!(rewritten.contains("EXCLUDED.email"), "{rewritten}");

        let mut strict = rewriter(strict_catalog(false));
        assert!(
            matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Replace(_)),
            "the canonical upsert must not be refused under reject"
        );

        // Row-wise, the same statement takes the tuple path.
        let mut strict = rewriter(strict_catalog(false));
        let action = strict
            .on_frame(
                b'Q',
                &query_frame(
                    "INSERT INTO users (id, email) VALUES (1, 'a@b.io') \
                     ON CONFLICT (id) DO UPDATE SET (email) = (EXCLUDED.email)",
                ),
            )
            .unwrap();
        assert!(matches!(action, FrameAction::Replace(_)), "row-wise upsert refused");

        for refused in [
            // Not listed by the INSERT, so `EXCLUDED.email` is the column's
            // own default and nothing sealed it.
            "INSERT INTO users (id) VALUES (1) \
             ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email",
            // A different column: sealed, if at all, under another transform.
            "INSERT INTO users (id, email) VALUES (1, 'a@b.io') \
             ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.id",
            // Not the EXCLUDED relation at all.
            "INSERT INTO users (id, email) VALUES (1, 'a@b.io') \
             ON CONFLICT (id) DO UPDATE SET email = users.name",
        ] {
            let mut strict = rewriter(strict_catalog(false));
            let action = strict.on_frame(b'Q', &query_frame(refused)).unwrap();
            assert!(refusal(&action).contains("protected column email"), "{refused}");
        }
    }

    /// The conflict action is reached even when the INSERT's own column list
    /// has nothing protected in it.
    #[test]
    fn on_conflict_do_update_is_reached_without_protected_insert_columns() {
        let mut rewriter = rewriter(catalog(false));
        let sql = rewritten_query(
            &mut rewriter,
            "INSERT INTO users (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET email = 'x@y.io'",
        )
        .expect("rewritten");
        assert!(!sql.contains("x@y.io"), "{sql}");
    }
}
