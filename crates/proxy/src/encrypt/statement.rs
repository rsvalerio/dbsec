//! The statement layer: one SQL text in, the rewritten text or a refusal out.
//!
//! [`QueryRewriter::rewrite_sql`] is the entry point the frame layer calls. It
//! tokenizes once, reads the session settings the text moves, parses, and then
//! dispatches each statement to the arm for its kind — which is where the
//! policy of this proxy is written down: an `INSERT` seals its values, an
//! `UPDATE` seals and rewrites, a `COPY` is a refusal site in one direction
//! and a rewrite site in the other.
//!
//! What is *not* here: the traversal of the predicates and subqueries a
//! statement contains (`predicate`, `query`) and the sealing of an individual
//! value (`seal`). This module decides which of those a statement kind needs;
//! it does not perform them.

use sqlparser::ast::{
    CopySource, Delete, FromTable, Insert, ObjectName, OnConflict, OnConflictAction, OnInsert,
    Query, Statement, TableFactor, TableWithJoins,
};
use sqlparser::dialect::PostgreSqlDialect;

use crate::portal::{ParamTransforms, RowKeySource};
use crate::Error;

use super::catalog::{normalize, Columns};
use super::lexer::{parse_tokens, reassemble, tokenize};
use super::scope::{ScopedTable, TableScope};
use super::seal::UpdateTarget;
use super::settings::{settings_moved, SettingMoved};
use super::unprotected::Unprotected;
use super::{
    AssignmentRow, AssignmentScope, QueryRewriter, Rejection, RewriteOutcome, SealedValues,
    SqlOutcome,
};

impl QueryRewriter {
    pub(super) fn rewrite_sql(&mut self, query: &[u8]) -> Result<SqlOutcome, Error> {
        let Ok(text) = std::str::from_utf8(query) else {
            return self.unprotected_sql(&Unprotected::NonUtf8);
        };
        // Session settings are read from the token stream rather than from the
        // parsed statements, because the parse cannot see them: sqlparser 0.53
        // does not parse `SET SCHEMA` at all, and `set_config('search_path', …)`
        // is an ordinary function call that can sit anywhere in any statement.
        // They stay grouped per statement so a move takes effect from the
        // statement that makes it onwards — a `SET` at the end of a batch must
        // not retroactively stop the write in front of it from being sealed.
        //
        // The parser reads those same tokens rather than lexing the text a
        // second time, so a rewritten statement is tokenized once.
        let dialect = PostgreSqlDialect {};
        let (moved, parsed) = match tokenize(&dialect, text) {
            Ok(tokens) => (settings_moved(&tokens), parse_tokens(&dialect, tokens, text)),
            // Text that does not tokenize does not parse either, so there is
            // nothing to read out of it beyond the error itself.
            Err(error) => (Vec::new(), Err(error)),
        };
        // The groups line up with the statements only when the tokenizer and
        // the parser saw the same batch. Unparseable text (where nothing is
        // rewritten, so no ordering can change an outcome) and any other
        // disagreement fall back to applying every move up front, which is the
        // conservative reading.
        let aligned = parsed.as_ref().is_ok_and(|statements| statements.len() == moved.len());
        // Whatever the startup packet moved is reported here, ahead of the
        // batch's own moves: it was already in force when this statement
        // arrived.
        let mut upfront = std::mem::take(&mut self.startup_moved);
        if !aligned {
            upfront.extend(moved.iter().flatten().copied());
        }
        match self.note_session_state(&upfront) {
            Ok(()) => {}
            Err(Rejection::Fatal(error)) => return Err(*error),
            Err(Rejection::Refused(message)) => return Ok(SqlOutcome::Refuse(message)),
        }
        let mut statements = match parsed {
            Ok(statements) => statements,
            Err(error) => return self.unprotected_sql(&Unprotected::Unparseable(&error)),
        };

        let mut params = ParamTransforms::default();
        let mut changed = vec![false; statements.len()];
        for (index, (statement, changed)) in statements.iter_mut().zip(&mut changed).enumerate() {
            let noted = if aligned { self.note_session_state(&moved[index]) } else { Ok(()) };
            match noted.and_then(|()| self.rewrite_statement(statement, &mut params)) {
                Ok(did_change) => *changed = did_change,
                Err(Rejection::Fatal(error)) => return Err(*error),
                Err(Rejection::Refused(message)) => return Ok(SqlOutcome::Refuse(message)),
            }
        }

        let rewritten = changed
            .iter()
            .any(|changed| *changed)
            .then(|| reassemble(text, &statements, &changed))
            .transpose()?;
        Ok(SqlOutcome::Rewrite(RewriteOutcome { rewritten, params }))
    }

    /// Records the session settings a statement moved, as read out of the SQL
    /// about to be relayed — or, on the session's first statement, what the
    /// startup packet had already moved before any SQL arrived. Once
    /// `search_path` stops making `public` the schema of an unqualified name,
    /// the write path stops resolving bare names at all;
    /// `standard_conforming_strings` is reported but changes no catalog
    /// assumption, because what it invalidates is the proxy's reading of the
    /// client's own literals.
    fn note_session_state(&mut self, moved: &[SettingMoved]) -> Result<(), Rejection> {
        for setting in moved {
            match setting {
                SettingMoved::SearchPath => {
                    self.search_path_trusted = false;
                    self.unprotected(&Unprotected::SearchPathChanged)?;
                }
                SettingMoved::EscapeStrings => {
                    self.escape_strings = true;
                    self.unprotected(&Unprotected::EscapeStringsChanged)?;
                }
            }
        }
        Ok(())
    }

    /// Dispatches one statement to the rewrite or refusal path of its kind.
    ///
    /// Every arm delegates, so what a statement kind does about protected
    /// columns is stated once, in a function named after that kind, and this
    /// match stays a map from statement to policy rather than the place the
    /// policies are written. The fallback `Ok(false)` is the deliberate
    /// default: a statement kind that cannot reach a protected value needs
    /// neither a rewrite nor a signal.
    pub(super) fn rewrite_statement(
        &self,
        statement: &mut Statement,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        match statement {
            Statement::Insert(insert) => self.rewrite_insert(insert, params),
            Statement::Update { .. } => self.rewrite_update(statement, params),
            Statement::Query(query) => self.rewrite_query(query, params),
            Statement::Delete(delete) => self.rewrite_delete(delete, params),
            Statement::Copy { source, to, .. } => self.rewrite_copy(source, *to, params),
            Statement::Merge { table, .. } => self.refuse_merge(table),
            Statement::Prepare { statement, .. } => self.refuse_prepare(statement),
            _ => Ok(false),
        }
    }

    /// The protected columns of an UPDATE's target, if the target is a plain
    /// named table this proxy protects.
    ///
    /// `None` for every other `TableFactor` — a derived table, a function, a
    /// `VALUES` list — none of which names a catalogued relation to seal
    /// against; their own subqueries are reached by
    /// [`Self::rewrite_derived_tables`] instead.
    fn update_columns(&self, table: &TableWithJoins) -> Result<Option<&Columns>, Rejection> {
        let TableFactor::Table { name, .. } = &table.relation else { return Ok(None) };
        self.table(name)
    }

    /// Seals an UPDATE's assignments and rewrites every predicate it carries.
    ///
    /// Takes the whole `Statement` rather than its four relevant fields
    /// because splitting them into arguments is what pushes the signature past
    /// what a reader can hold; the `else` arm is unreachable — only the
    /// `Statement::Update` arm of [`Self::rewrite_statement`] calls this — and
    /// `Ok(false)` is the same "nothing to do" the fallback arm returns.
    fn rewrite_update(
        &self,
        statement: &mut Statement,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let Statement::Update { table, assignments, from, selection, .. } = statement else {
            return Ok(false);
        };
        let mut changed = false;
        if let Some(columns) = self.update_columns(table)? {
            let row = self.update_row(
                &UpdateTarget {
                    table,
                    from: from.as_ref(),
                    selection: selection.as_ref(),
                    assignments,
                },
                columns,
            );
            let target = AssignmentScope::of(columns, row);
            changed |= self.seal_assignments(assignments, &target, params)?;
        }
        // `UPDATE ... FROM other` is a join: the predicate resolves names
        // against the joined relation as well as the target, so a searchable
        // column of *that* relation is as much a rewrite site as the target's
        // own. Dropping it with the `..` left the comparison relayed verbatim
        // — no rewrite, and no signal.
        let scope = self.scope(std::iter::once(&*table).chain(from.as_ref()))?;
        // A join constraint in that FROM resolves against the same scope the
        // WHERE does, so it is the same rewrite site — and one only
        // `rewrite_select` used to walk.
        changed |= self.rewrite_join_conditions(
            std::iter::once(&mut *table).chain(from.as_mut()),
            &scope,
            params,
        )?;
        if let Some(selection) = selection {
            changed |= self.rewrite_predicate(selection, &scope, params)?;
        }
        // `SET x = (SELECT ...)` on an unprotected column still hides a query
        // whose own predicates need rewriting.
        for assignment in assignments.iter_mut() {
            changed |= self.rewrite_nested_queries(&mut assignment.value, params)?;
        }
        changed |= self.rewrite_derived_tables(std::iter::once(table).chain(from), params)?;
        Ok(changed)
    }

    /// Rewrites the predicates of a DELETE.
    ///
    /// There is nothing to seal — a DELETE carries no values — so every
    /// rewrite site here is a comparison that would otherwise be made against
    /// the stored form.
    fn rewrite_delete(
        &self,
        delete: &mut Delete,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        // `USING` is the DELETE spelling of `UPDATE ... FROM`, and it is a
        // separate field: a predicate over the joined relation resolves
        // against it, so it belongs in the scope too. Left out, `DELETE FROM
        // sessions USING users WHERE users.email = $1` compares plaintext
        // against the stored form and deletes nothing — and its `<>` inversion
        // deletes everything.
        let scope =
            self.scope(delete_tables(&delete.from).iter().chain(delete.using.iter().flatten()))?;
        let mut changed = false;
        if let Some(selection) = delete.selection.as_mut() {
            changed |= self.rewrite_predicate(selection, &scope, params)?;
        }
        let tables = delete_tables_mut(&mut delete.from);
        // Same as the UPDATE arm: a `USING a JOIN b ON …` constraint resolves
        // against this scope and is as much a rewrite site as the WHERE.
        changed |= self.rewrite_join_conditions(
            tables.iter_mut().chain(delete.using.iter_mut().flatten()),
            &scope,
            params,
        )?;
        changed |= self.rewrite_derived_tables(
            tables.iter_mut().chain(delete.using.iter_mut().flatten()),
            params,
        )?;
        Ok(changed)
    }

    /// Classifies — and, for a query source on the way out, rewrites — a COPY.
    fn rewrite_copy(
        &self,
        source: &mut CopySource,
        to: bool,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        match source {
            CopySource::Table { table_name, .. } => {
                self.refuse_copy_table(table_name, to)?;
                Ok(false)
            }
            CopySource::Query(query) => self.rewrite_copy_query(query, to, params),
        }
    }

    /// Signals a `COPY table` in either direction over a table the proxy
    /// protects.
    ///
    /// The two directions ask different questions of the catalog. `COPY … FROM
    /// STDIN` is a write, so what matters is whether a value would have needed
    /// sealing — a plaintext bulk load into a mask-only column is correct and
    /// must not be refused. `COPY … TO` is a read, and its rows leave as
    /// `CopyData` frames the read path relays verbatim, so a mask-only column
    /// leaves as the plaintext its mask exists to hide.
    fn refuse_copy_table(&self, table_name: &ObjectName, to: bool) -> Result<(), Rejection> {
        let protected =
            if to { self.reads_protected(table_name)? } else { self.table(table_name)?.is_some() };
        if protected {
            self.unprotected(&Unprotected::Copy { table: table_name, to })?;
        }
        Ok(())
    }

    /// Classifies and rewrites `COPY (SELECT ...) TO STDOUT`.
    ///
    /// PostgreSQL only allows a query source in the *out* direction, and its
    /// rows leave as `CopyData` frames — which the read path relays verbatim,
    /// because only `DataRow` carries the column identity decryption needs. So
    /// this form streams the stored value of every protected column it
    /// projects, and it used to do so with no signal at all: the classifier
    /// looked at `CopySource::Table` only, so `reject` refused `COPY users TO
    /// STDOUT` and relayed `COPY (SELECT email FROM users) TO STDOUT`.
    ///
    /// The query is classified *and* rewritten. Classified first, so `reject`
    /// refuses the leak before anything is rendered; rewritten second, because
    /// under `warn` the statement is relayed and its predicates are ordinary
    /// predicates — a searchable equality left alone compares the client's
    /// plaintext against the stored `blind_index || envelope` and matches no
    /// row, which is the failure [`Self::rewrite_nested_queries`] documents as
    /// the unsafe one.
    ///
    /// Only the `TO` direction is rewritten, and that is what keeps the
    /// re-rendering safe: PostgreSQL allows a query source only on the way
    /// out, so a statement that changes here is never a `COPY ... FROM STDIN`
    /// — the one COPY shape with no wire-valid rendering through sqlparser's
    /// `Display` (see [`parse_sql`](super::lexer::parse_sql), which parses it only by appending a
    /// terminator the wire cannot carry). Anything not rewritten keeps its
    /// original source text verbatim ([`reassemble`]), and anything that is
    /// rewritten is re-parsed and compared before it is sent
    /// ([`render_validated`](super::lexer::render_validated)).
    fn rewrite_copy_query(
        &self,
        query: &mut Query,
        to: bool,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        for table in self.copied_protected_tables(query)? {
            self.unprotected(&Unprotected::CopyQuery { table })?;
        }
        if to {
            return self.rewrite_query(query, params);
        }
        Ok(false)
    }

    /// Signals a MERGE into a protected table.
    ///
    /// MERGE writes through the same `Assignment`s an UPDATE does, but its
    /// values come from the source relation rather than literals, so there is
    /// nothing the rewrite could seal — it is a refusal site, not a rewrite
    /// site.
    fn refuse_merge(&self, table: &TableFactor) -> Result<bool, Rejection> {
        let TableFactor::Table { name, .. } = table else { return Ok(false) };
        if self.table(name)?.is_some() {
            self.unprotected(&Unprotected::Unsupported { table: name, shape: "MERGE" })?;
        }
        Ok(false)
    }

    /// Signals a PREPARE whose target is a protected table.
    ///
    /// The literals of a PREPARE could be sealed, but its parameters are bound
    /// by a later EXECUTE the proxy cannot tie back to this statement, so half
    /// of the values would still land in plaintext.
    fn refuse_prepare(&self, statement: &Statement) -> Result<bool, Rejection> {
        let Some(name) = write_target(statement) else { return Ok(false) };
        if self.table(name)?.is_some() {
            self.unprotected(&Unprotected::Unsupported { table: name, shape: "PREPARE" })?;
        }
        Ok(false)
    }

    fn rewrite_insert(
        &self,
        insert: &mut Insert,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let Some(columns) = self.table(&insert.table_name)? else { return Ok(false) };
        let mut changed = false;
        let mut sealed = SealedValues::default();
        if insert.columns.is_empty() {
            // Without a column list the values cannot be matched to columns:
            // the table's own column order is not something the proxy knows.
            self.unprotected(&Unprotected::NoColumnList(&insert.table_name))?;
        } else {
            sealed = self.rewrite_insert_values(insert, columns, params)?;
            changed |= sealed.changed;
        }
        // The conflict action's `WHERE` is a predicate over the target table,
        // exactly like an UPDATE's own, so it is resolved against the same
        // scope. The alias an `INSERT INTO t AS x` gives that table is the
        // only name the predicate can qualify with, so the scope carries it.
        let scope = TableScope {
            tables: vec![ScopedTable {
                alias: insert.table_alias.as_ref().map(normalize),
                name: insert.table_name.0.iter().map(normalize).collect(),
                columns,
                // The write lookup above already resolved the name, so the
                // read direction is fetched without repeating its
                // `search_path` guard — reaching here means the name resolved.
                read_columns: self.catalog.read_columns_of(&insert.table_name),
            }],
        };
        // Which row the conflict action writes, read before `insert.on` is
        // borrowed mutably below. Hardcoding `RowKeySource::None` here sealed
        // every upsert-written value with cell-only binding on a table whose
        // `INSERT`ed values a few lines above were bound to their row — the
        // same statement writing `DBS3` for the inserted row and `DBS2` for
        // the conflict-updated one, with no site reported for either policy.
        let row = match insert.on.as_ref() {
            Some(OnInsert::OnConflict(OnConflict {
                conflict_target,
                action: OnConflictAction::DoUpdate(update),
            })) => self.conflict_row(insert, conflict_target.as_ref(), &update.assignments),
            Some(OnInsert::DuplicateKeyUpdate(assignments)) => {
                self.conflict_row(insert, None, assignments)
            }
            _ => AssignmentRow::Known(RowKeySource::None),
        };
        let target = AssignmentScope { row, columns, sealed };
        // The conflict action writes the same columns on every existing row,
        // and it is a plain assignment list — the UPDATE path handles it.
        match insert.on.as_mut() {
            Some(OnInsert::OnConflict(OnConflict {
                action: OnConflictAction::DoUpdate(update),
                ..
            })) => {
                changed |= self.seal_assignments(&mut update.assignments, &target, params)?;
                if let Some(selection) = update.selection.as_mut() {
                    changed |= self.rewrite_predicate(selection, &scope, params)?;
                }
            }
            Some(OnInsert::DuplicateKeyUpdate(assignments)) => {
                changed |= self.seal_assignments(assignments, &target, params)?;
            }
            _ => {}
        }
        Ok(changed)
    }
}

/// The relations a DELETE deletes from.
///
/// `FROM` is optional in PostgreSQL's `DELETE t USING …` spelling, and
/// sqlparser keeps the two in separate variants of the same enum; nothing
/// downstream cares which was written, so both collapse to the same slice.
fn delete_tables(from: &FromTable) -> &[TableWithJoins] {
    match from {
        FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables) => tables,
    }
}

/// The mutable twin of [`delete_tables`], for the rewrite that follows the
/// scope built from it.
fn delete_tables_mut(from: &mut FromTable) -> &mut [TableWithJoins] {
    match from {
        FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables) => tables,
    }
}

/// The table a write statement targets, for the shapes the rewrite declines
/// to handle itself.
fn write_target(statement: &Statement) -> Option<&ObjectName> {
    let relation = match statement {
        Statement::Insert(insert) => return Some(&insert.table_name),
        Statement::Update { table, .. } => &table.relation,
        Statement::Merge { table, .. } => table,
        _ => return None,
    };
    match relation {
        TableFactor::Table { name, .. } => Some(name),
        _ => None,
    }
}
