//! The encrypt path (milestone 5): client→upstream interception.
//!
//! Simple protocol: `Query` SQL is parsed with sqlparser and literals bound
//! to protected columns in INSERT/UPDATE (including `ON CONFLICT DO UPDATE`)
//! are sealed in place (as `\x` hex bytea literals). Extended protocol:
//! `Parse` remembers which parameter placeholders feed protected columns (and
//! seals any inline literals); `Bind` seals those parameters. Seal errors fail
//! the session.
//!
//! The extended protocol's per-session state does not live here but in
//! [`crate::portal`], which the read path shares: this direction is the only
//! one that sees which statement a portal was bound to and which portal is
//! being executed, and the read path cannot decrypt a DataRow correctly
//! without knowing both. Every expectation recorded there is recorded only for
//! a frame that is actually forwarded upstream — a refused statement is
//! answered by the proxy and never reaches the backend, so queueing a response
//! for it would leave the read path waiting for an answer nobody will send.
//!
//! # Statements the rewrite cannot cover
//!
//! Every place a write to a protected column is *not* rewritten is an
//! [`Unprotected`] site, and every one of them goes through
//! [`QueryRewriter::unprotected`] — the single decision point that either logs
//! a warning and lets the plaintext through, or refuses the statement with a
//! PostgreSQL ErrorResponse. Which one is `on_unprotected` in the config; see
//! [`crate::config::OnUnprotected`] for the default and its rationale. The
//! sites are: non-UTF-8 and unparseable SQL, `INSERT` without a column list,
//! `INSERT ... SELECT`, `COPY`, `MERGE`, `PREPARE` of a write, a non-literal
//! expression bound to a protected column, an unqualified name under a
//! changed `search_path`, and a predicate over a searchable column the
//! rewriter cannot turn into a blind-index match.
//!
//! A refusal is a statement-level error, not a dropped connection: the client
//! gets ErrorResponse + ReadyForQuery (or, in the extended protocol,
//! ErrorResponse and then the frames up to `Sync` discarded, exactly as the
//! backend would). Two consequences worth knowing:
//!
//! - The backend never saw the statement, so its own transaction is still
//!   open. The ReadyForQuery the proxy synthesizes reports the aborted state
//!   when a transaction was in progress, so the client rolls back rather than
//!   committing around the hole.
//! - In a *pipelined* session the refusal can reach the client before
//!   responses to earlier messages that are still in flight upstream. The
//!   messages are well-formed and the session recovers at the next
//!   ReadyForQuery, but the error may appear against the wrong request.
//!
//! # Query shapes with searchable equality
//!
//! `col = <value>` and `col IN (<values>)` over a searchable column become a
//! blind-index prefix match, as does `col = ANY(ARRAY[...])` with a literal
//! array. `col = ANY($1)` — the whole list bound as one array parameter, which
//! is how sqlx and asyncpg express a multi-value lookup — is rewritten the
//! same way, with the array decoded, indexed element by element and re-encoded
//! as `bytea[]` at Bind time ([`index_array`]). They are rewritten wherever
//! they appear in a `SELECT`/`UPDATE`/`DELETE`: `WHERE` and `HAVING`,
//! `JOIN ... ON` constraints, CTE bodies, both branches of a
//! `UNION`/`INTERSECT`/`EXCEPT`, and derived-table subqueries. Anything else
//! that mentions a searchable column — `LIKE`, ordering comparisons,
//! `IN (SELECT ...)`, `= ANY(SELECT ...)` — is an [`Unprotected`] site rather
//! than a silent no-op, because comparing a client's plaintext against the
//! stored form matches no row and reads as an empty result rather than an
//! error. So is an array parameter the codec cannot decode faithfully: the
//! signal moves to Bind time, but it is the same signal.
//!
//! # SQL text fidelity
//!
//! sqlparser's `Display` is not a guaranteed round-trip of its input:
//! comments, whitespace, quoting style and dollar-quoted bodies are all
//! normalized away. So only statements the rewrite actually changed are
//! re-rendered; every other statement in a multi-statement `Query`, and all
//! text between statements, is relayed exactly as the client wrote it. What
//! is re-rendered is re-parsed and compared against the AST it came from
//! before it goes on the wire ([`render_validated`]) — a divergence fails the
//! session instead of executing SQL the client did not write.
//!
//! # Logging
//!
//! Every value flowing through here is, by construction, the plaintext of a
//! column configured to be unreadable at rest, and logs are at rest somewhere
//! with weaker access control than the database. So no event in this module
//! carries a value, or anything derived from one.
//!
//! Audited set — these are every field every `tracing` call here emits:
//!
//! | Field | What it is |
//! |---|---|
//! | `table`, `column` | SQL identifiers, as written by the client |
//! | `direction` | `"to"` or `"from"`, for `COPY` |
//! | `shape` | an AST discriminant such as `"function call"` ([`expr_shape`]) |
//! | `error_kind` | the sqlparser error *variant* ([`parser_error_kind`]) — never its message, which embeds the offending token |
//! | `statements` | a count |
//!
//! Anything added later must stay inside that set;
//! `no_event_from_the_write_path_carries_a_plaintext_value` is the test that
//! keeps it honest by driving every site and grepping the emitted events.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use dbsec_core::pgwire;
use dbsec_core::transform::{FieldTransform, WireForm};
use sqlparser::ast::{
    Assignment, AssignmentTarget, Expr, Ident, Insert, JoinConstraint, JoinOperator, ObjectName,
    OnConflict, OnConflictAction, OnInsert, Query, Select, SetExpr, Statement, TableFactor,
    TableWithJoins, Value,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::{Parser, ParserError};

use crate::columns::ProtectedColumn;
use crate::config::OnUnprotected;
use crate::portal::{ParamAction, ParamTransforms, SessionPortals, Target};
use crate::session::FrameAction;
use crate::Error;

/// The protected columns of one table, keyed by column name.
type Columns = HashMap<String, Arc<dyn FieldTransform>>;

/// Protected columns keyed by name for SQL matching:
/// `(schema, table) → column → transform`.
pub struct WriteCatalog {
    tables: HashMap<(String, String), Columns>,
    /// Protected table names without their schema, so an unqualified SQL name
    /// can be recognised as *possibly* protected even when `search_path` no
    /// longer says which schema it resolves to.
    bare_names: HashSet<String>,
    on_unprotected: OnUnprotected,
}

impl WriteCatalog {
    pub fn new(columns: &[ProtectedColumn], on_unprotected: OnUnprotected) -> Self {
        let mut tables: HashMap<_, Columns> = HashMap::new();
        let mut bare_names = HashSet::new();
        // Mask-only columns have no transform; their writes pass through.
        for column in columns {
            let Some(transform) = &column.transform else { continue };
            bare_names.insert(column.table.clone());
            tables
                .entry((column.schema.clone(), column.table.clone()))
                .or_default()
                .insert(column.column.clone(), transform.clone());
        }
        Self { tables, bare_names, on_unprotected }
    }

    /// Looks a table up the way Postgres would resolve the SQL name: the last
    /// identifier is the table, the one before it the schema, and bare names
    /// fall back to `public` — which holds only while the session's
    /// `search_path` does, hence [`QueryRewriter::table`].
    fn table(&self, name: &ObjectName) -> Option<&Columns> {
        let mut parts = name.0.iter().rev();
        let table = normalize(parts.next()?);
        let schema = parts.next().map_or_else(|| "public".to_owned(), normalize);
        self.tables.get(&(schema, table))
    }

    /// Whether an unqualified name matches a protected table in *some* schema.
    fn may_be_protected(&self, name: &ObjectName) -> bool {
        name.0.last().is_some_and(|ident| self.bare_names.contains(&normalize(ident)))
    }
}

/// PG folds unquoted identifiers to lowercase; quoted ones stay verbatim.
fn normalize(ident: &Ident) -> String {
    if ident.quote_style.is_some() {
        ident.value.clone()
    } else {
        ident.value.to_lowercase()
    }
}

/// Why a rewrite stopped: the session cannot continue, or this one statement
/// is refused and the client is told why.
enum Rejection {
    /// A crypto or wire failure: fail the session rather than relay anything.
    /// Boxed because this variant travels in the `Err` of most of the
    /// rewrite's return types, and [`Error`] is large enough that inlining it
    /// would make every one of them wide (`clippy::result_large_err`).
    Fatal(Box<Error>),
    /// `on_unprotected = "reject"` met a statement it will not let through.
    Refused(String),
}

impl From<Error> for Rejection {
    fn from(error: Error) -> Self {
        Self::Fatal(Box::new(error))
    }
}

/// What one SQL text turned into.
enum SqlOutcome {
    /// Relay it (`rewritten` is `None`) or send the replacement text.
    Rewrite(RewriteOutcome),
    /// Refuse it with this message.
    Refuse(String),
}

/// Per-session write-path state: rewrites Query/Parse SQL and Bind
/// parameters using the shared catalog. What it learns about statements and
/// portals goes into [`SessionPortals`], which the read path shares.
pub struct QueryRewriter {
    catalog: Arc<WriteCatalog>,
    /// Prepared statements, portals and the responses the backend still owes,
    /// shared with the read path. Bounded — every key here is client-chosen.
    portals: Arc<SessionPortals>,
    /// The backend's transaction status, as last seen by the upstream→client
    /// relay. Read only to pick the status byte of a synthesized
    /// ReadyForQuery, so a relaxed load of a possibly stale value is exactly
    /// as good as a synchronized one.
    tx_status: Arc<AtomicU8>,
    /// Whether unqualified table names still resolve to `public`.
    search_path_trusted: bool,
    /// Set after refusing an extended-protocol message: the backend never saw
    /// it, so the proxy plays the backend's part and discards the rest of the
    /// batch up to `Sync`.
    awaiting_sync: bool,
}

impl QueryRewriter {
    pub fn new(
        catalog: Arc<WriteCatalog>,
        portals: Arc<SessionPortals>,
        tx_status: Arc<AtomicU8>,
        search_path_trusted: bool,
    ) -> Self {
        Self { catalog, portals, tx_status, search_path_trusted, awaiting_sync: false }
    }

    /// Inspects one client→upstream frame, returning what the relay should do
    /// with it.
    pub fn on_frame(&mut self, msg_type: u8, body: &[u8]) -> Result<FrameAction, Error> {
        if self.awaiting_sync {
            return Ok(self.discard_until_sync(msg_type));
        }
        match msg_type {
            b'Q' => {
                let mut sql = body;
                let query = pgwire::take_cstr(&mut sql).map_err(Error::Wire)?;
                match self.rewrite_sql(query)? {
                    // Refused here, so the backend never sees it and owes no
                    // ReadyForQuery: the proxy answers with its own, and no
                    // batch is recorded.
                    SqlOutcome::Refuse(message) => {
                        let mut reply = error_response(&message);
                        reply.extend_from_slice(&self.ready_for_query());
                        Ok(FrameAction::Reply(reply))
                    }
                    SqlOutcome::Rewrite(outcome) => {
                        // A simple Query is its own batch: the backend answers
                        // it with a ReadyForQuery, which is where the read
                        // path resynchronises.
                        self.portals.expect_batch()?;
                        Ok(match outcome.rewritten {
                            None => FrameAction::Relay,
                            Some(rewritten) => {
                                let mut new_body = rewritten.into_bytes();
                                new_body.push(0);
                                FrameAction::Replace(new_body)
                            }
                        })
                    }
                }
            }
            b'P' => {
                let parse = pgwire::parse_parse(body)?;
                let outcome = match self.rewrite_sql(parse.query)? {
                    SqlOutcome::Refuse(message) => {
                        // The backend is not going to answer this batch, so
                        // the proxy owns the error state until Sync. Nothing
                        // is recorded for this statement: the frame is not
                        // forwarded, so no response is owed for it.
                        self.awaiting_sync = true;
                        return Ok(FrameAction::Reply(error_response(&message)));
                    }
                    SqlOutcome::Rewrite(outcome) => outcome,
                };
                self.portals.parse(parse.statement, outcome.params)?;
                Ok(match outcome.rewritten {
                    None => FrameAction::Relay,
                    Some(sql) => FrameAction::Replace(pgwire::encode_parse(
                        parse.statement,
                        sql.as_bytes(),
                        parse.param_types,
                    )),
                })
            }
            b'B' => self.bind(body),
            b'D' => {
                // Describe: the RowDescription it provokes is what tells the
                // read path which columns of this statement are protected.
                let (target, name) = describe_target(body)?;
                self.portals.expect_describe(target, name)?;
                Ok(FrameAction::Relay)
            }
            b'E' => {
                let mut rest = body;
                let portal = pgwire::take_cstr(&mut rest)?;
                self.portals.expect_execute(portal)?;
                Ok(FrameAction::Relay)
            }
            b'S' => {
                self.portals.expect_batch()?;
                Ok(FrameAction::Relay)
            }
            // CopyData, CopyDone, CopyFail: the client only sends these in
            // copy-in mode, which is where the backend ignores the Sync it has
            // already pipelined — see [`SessionPortals::copy_data`].
            b'd' | b'c' | b'f' => {
                self.portals.copy_data();
                Ok(FrameAction::Relay)
            }
            b'C' => {
                // Close: 'S' = statement, 'P' = portal.
                let (target, name) = describe_target(body)?;
                match target {
                    Target::Statement => self.portals.close_statement(name),
                    Target::Portal => self.portals.close_portal(name),
                }
                Ok(FrameAction::Relay)
            }
            _ => Ok(FrameAction::Relay),
        }
    }

    fn bind(&mut self, body: &[u8]) -> Result<FrameAction, Error> {
        let bind = pgwire::parse_bind(body)?;
        // Recorded even when the statement is unknown to the rewriter: the
        // read path still needs to know which statement this portal names.
        let Some(params) = self.portals.bind(bind.portal, bind.statement)? else {
            return Ok(FrameAction::Relay);
        };
        if params.is_empty() {
            return Ok(FrameAction::Relay);
        }
        let mut values: Vec<Option<Cow<'_, [u8]>>> =
            bind.params.iter().map(|p| p.map(Cow::Borrowed)).collect();
        let mut refusal = None;
        for (index, action) in params.iter() {
            let binary = bind.param_format(*index) == 1;
            let Some(Some(value)) = values.get_mut(*index) else { continue };
            let replacement = match action {
                ParamAction::Seal(transform) => {
                    encode_param(transform.seal(value)?, transform.wire(), binary)
                }
                ParamAction::SearchIndex(transform) => {
                    let Some(token) = transform.search_index(value)? else {
                        return Err(Error::Wire(dbsec_core::Error::Malformed));
                    };
                    // The index prefix is BYTEA regardless of the transform's
                    // own stored form.
                    encode_param(token, WireForm::Bytea, binary)
                }
                // The array is already in the parameter's own format: the
                // codec re-encodes it in the shape it decoded.
                ParamAction::SearchIndexArray { transform, column } => {
                    match index_array(value, binary, transform)? {
                        Some(indexed) => indexed,
                        // Nothing about this array can be indexed faithfully.
                        // The SQL already matches the blind index, so leaving
                        // the plaintext array is the "matches no rows" outcome
                        // the warn path describes; strict mode refuses it.
                        None => {
                            refusal = Some(Unprotected::Predicate {
                                column: column.to_string(),
                                shape: "= ANY bound array",
                            });
                            continue;
                        }
                    }
                }
            };
            *value = Cow::Owned(replacement);
        }
        // Every other parameter of this Bind is still transformed on the warn
        // path: a sealed parameter relayed as plaintext because some *other*
        // parameter could not be indexed would write the very thing this proxy
        // exists to prevent.
        if let Some(site) = refusal {
            match self.unprotected(&site) {
                Ok(()) => {}
                Err(Rejection::Refused(message)) => {
                    // Same shape as a refused Parse: the backend never sees
                    // the Bind, so the proxy owns the batch until Sync.
                    self.awaiting_sync = true;
                    return Ok(FrameAction::Reply(error_response(&message)));
                }
                Err(Rejection::Fatal(error)) => return Err(*error),
            }
        }
        Ok(FrameAction::Replace(pgwire::encode_bind(
            bind.portal,
            bind.statement,
            &bind.param_formats,
            &values,
            bind.result_formats,
        )?))
    }

    /// After a refusal the backend has no work queued for this batch, so the
    /// proxy mirrors what the backend does in its own error state: drop
    /// everything up to `Sync`, then answer with ReadyForQuery.
    fn discard_until_sync(&mut self, msg_type: u8) -> FrameAction {
        match msg_type {
            b'S' => {
                self.awaiting_sync = false;
                FrameAction::Reply(self.ready_for_query())
            }
            // Terminate ends the session; the backend should see it.
            b'X' => {
                self.awaiting_sync = false;
                FrameAction::Relay
            }
            _ => FrameAction::Reply(Vec::new()),
        }
    }

    /// The ReadyForQuery a refusal answers with. The backend never saw the
    /// statement, so its transaction is still open: reporting the aborted
    /// state is what makes the client roll back instead of committing the
    /// rest of a transaction whose protected write did not happen.
    fn ready_for_query(&self) -> Vec<u8> {
        let status = match self.tx_status.load(Ordering::Relaxed) {
            b'T' | b'E' => b'E',
            _ => b'I',
        };
        frame(b'Z', &[status])
    }

    /// The single decision point for every statement the proxy cannot
    /// protect: warn and let it through, or refuse it.
    fn unprotected(&self, site: &Unprotected<'_>) -> Result<(), Rejection> {
        match self.catalog.on_unprotected {
            OnUnprotected::Warn => {
                site.warn();
                Ok(())
            }
            OnUnprotected::Reject => Err(Rejection::Refused(site.message())),
        }
    }

    /// Same decision, for the sites that give up on the whole SQL text before
    /// any statement is reached.
    fn unprotected_sql(&self, site: &Unprotected<'_>) -> Result<SqlOutcome, Error> {
        match self.unprotected(site) {
            Ok(()) => Ok(SqlOutcome::Rewrite(RewriteOutcome::passthrough())),
            Err(Rejection::Refused(message)) => Ok(SqlOutcome::Refuse(message)),
            Err(Rejection::Fatal(error)) => Err(*error),
        }
    }

    /// Resolves a table name against the catalog, refusing to guess when the
    /// session's `search_path` has moved out from under an unqualified name:
    /// sealing for the wrong table writes a value the read path can never
    /// resolve, which is worse than not sealing at all.
    fn table(&self, name: &ObjectName) -> Result<Option<&Columns>, Rejection> {
        if self.search_path_trusted || name.0.len() > 1 {
            return Ok(self.catalog.table(name));
        }
        if self.catalog.may_be_protected(name) {
            self.unprotected(&Unprotected::SearchPath(name))?;
        }
        Ok(None)
    }

    fn rewrite_sql(&mut self, query: &[u8]) -> Result<SqlOutcome, Error> {
        let Ok(text) = std::str::from_utf8(query) else {
            return self.unprotected_sql(&Unprotected::NonUtf8);
        };
        let mut statements = match parse_sql(text) {
            Ok(statements) => statements,
            Err(error) => return self.unprotected_sql(&Unprotected::Unparseable(&error)),
        };

        let mut params = ParamTransforms::default();
        let mut changed = vec![false; statements.len()];
        for (statement, changed) in statements.iter_mut().zip(&mut changed) {
            let result = self
                .note_session_state(statement)
                .and_then(|()| self.rewrite_statement(statement, &mut params));
            match result {
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

    /// Watches for the session settings the catalog's assumptions depend on.
    /// `search_path` is the only one today: once it stops making `public` the
    /// schema of an unqualified name, the write path stops resolving bare
    /// names at all.
    fn note_session_state(&mut self, statement: &Statement) -> Result<(), Rejection> {
        let Statement::SetVariable { variables, value, .. } = statement else { return Ok(()) };
        let touches_search_path = variables
            .iter()
            .any(|name| name.0.last().is_some_and(|ident| normalize(ident) == "search_path"));
        if !touches_search_path || is_default_search_path(value) {
            return Ok(());
        }
        self.search_path_trusted = false;
        self.unprotected(&Unprotected::SearchPathChanged)
    }

    fn rewrite_statement(
        &self,
        statement: &mut Statement,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        match statement {
            Statement::Insert(insert) => self.rewrite_insert(insert, params),
            Statement::Update { table, assignments, selection, .. } => {
                let mut changed = false;
                if let TableFactor::Table { name, .. } = &table.relation {
                    if let Some(columns) = self.table(name)? {
                        changed |= self.seal_assignments(assignments, columns, params)?;
                    }
                }
                let scope = self.scope(std::slice::from_ref(table))?;
                if let Some(selection) = selection {
                    changed |= self.rewrite_selection(selection, &scope, params)?;
                }
                Ok(changed)
            }
            Statement::Query(query) => self.rewrite_query(query, params),
            Statement::Delete(delete) => {
                let tables = match &delete.from {
                    sqlparser::ast::FromTable::WithFromKeyword(tables)
                    | sqlparser::ast::FromTable::WithoutKeyword(tables) => tables,
                };
                let scope = self.scope(tables)?;
                let mut changed = false;
                if let Some(selection) = delete.selection.as_mut() {
                    changed |= self.rewrite_selection(selection, &scope, params)?;
                }
                Ok(changed)
            }
            Statement::Copy { source, to, .. } => {
                if let sqlparser::ast::CopySource::Table { table_name, .. } = source {
                    if self.table(table_name)?.is_some() {
                        self.unprotected(&Unprotected::Copy { table: table_name, to: *to })?;
                    }
                }
                Ok(false)
            }
            // MERGE writes through the same `Assignment`s an UPDATE does, but
            // its values come from the source relation rather than literals,
            // so there is nothing the rewrite could seal — it is a refusal
            // site, not a rewrite site.
            Statement::Merge { table, .. } => {
                if let TableFactor::Table { name, .. } = table {
                    if self.table(name)?.is_some() {
                        self.unprotected(&Unprotected::Unsupported {
                            table: name,
                            shape: "MERGE",
                        })?;
                    }
                }
                Ok(false)
            }
            // The literals of a PREPARE could be sealed, but its parameters
            // are bound by a later EXECUTE the proxy cannot tie back to this
            // statement, so half of the values would still land in plaintext.
            Statement::Prepare { statement, .. } => {
                if let Some(name) = write_target(statement) {
                    if self.table(name)?.is_some() {
                        self.unprotected(&Unprotected::Unsupported {
                            table: name,
                            shape: "PREPARE",
                        })?;
                    }
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    fn rewrite_insert(
        &self,
        insert: &mut Insert,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let Some(columns) = self.table(&insert.table_name)? else { return Ok(false) };
        let mut changed = false;
        if insert.columns.is_empty() {
            // Without a column list the values cannot be matched to columns:
            // the table's own column order is not something the proxy knows.
            self.unprotected(&Unprotected::NoColumnList(&insert.table_name))?;
        } else {
            changed |= self.rewrite_insert_values(insert, columns, params)?;
        }
        // The conflict action writes the same columns on every existing row,
        // and it is a plain assignment list — the UPDATE path handles it.
        match insert.on.as_mut() {
            Some(OnInsert::OnConflict(OnConflict {
                action: OnConflictAction::DoUpdate(update),
                ..
            })) => {
                changed |= self.seal_assignments(&mut update.assignments, columns, params)?;
            }
            Some(OnInsert::DuplicateKeyUpdate(assignments)) => {
                changed |= self.seal_assignments(assignments, columns, params)?;
            }
            _ => {}
        }
        Ok(changed)
    }

    fn rewrite_insert_values(
        &self,
        insert: &mut Insert,
        columns: &Columns,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let protected: Vec<(usize, &str, Arc<dyn FieldTransform>)> = insert
            .columns
            .iter()
            .enumerate()
            .filter_map(|(position, ident)| {
                let name = normalize(ident);
                columns
                    .get(&name)
                    .map(|transform| (position, ident.value.as_str(), transform.clone()))
            })
            .collect();
        if protected.is_empty() {
            return Ok(false);
        }
        let table = insert.table_name.clone();
        let Some(source) = insert.source.as_mut() else { return Ok(false) };
        let SetExpr::Values(values) = source.body.as_mut() else {
            self.unprotected(&Unprotected::InsertFromSelect(&table))?;
            return Ok(false);
        };
        let mut changed = false;
        for row in &mut values.rows {
            for (position, column, transform) in &protected {
                if let Some(expr) = row.get_mut(*position) {
                    changed |= self.seal_expr(expr, transform, column, params)?;
                }
            }
        }
        Ok(changed)
    }

    /// Seals every assignment that targets a protected column. Shared by
    /// `UPDATE` and by `INSERT ... ON CONFLICT DO UPDATE`.
    fn seal_assignments(
        &self,
        assignments: &mut [Assignment],
        columns: &Columns,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let mut changed = false;
        for Assignment { target, value } in assignments {
            let AssignmentTarget::ColumnName(column) = target else { continue };
            let Some(ident) = column.0.last() else { continue };
            let Some(transform) = columns.get(&normalize(ident)) else { continue };
            let transform = transform.clone();
            let name = ident.value.clone();
            changed |= self.seal_expr(value, &transform, &name, params)?;
        }
        Ok(changed)
    }

    /// Walks a query: CTE bodies, set-operation branches and the select
    /// itself, so a searchable predicate is rewritten wherever it sits.
    fn rewrite_query(
        &self,
        query: &mut Query,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let mut changed = false;
        if let Some(with) = query.with.as_mut() {
            for cte in &mut with.cte_tables {
                changed |= self.rewrite_query(&mut cte.query, params)?;
            }
        }
        changed |= self.rewrite_set_expr(&mut query.body, params)?;
        Ok(changed)
    }

    fn rewrite_set_expr(
        &self,
        body: &mut SetExpr,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        match body {
            SetExpr::Select(select) => self.rewrite_select(select, params),
            SetExpr::Query(query) => self.rewrite_query(query, params),
            SetExpr::SetOperation { left, right, .. } => {
                let left = self.rewrite_set_expr(left, params)?;
                let right = self.rewrite_set_expr(right, params)?;
                Ok(left | right)
            }
            // A data-modifying CTE: `WITH x AS (INSERT ... RETURNING ...)`.
            SetExpr::Insert(statement) | SetExpr::Update(statement) => {
                self.rewrite_statement(statement, params)
            }
            SetExpr::Values(_) | SetExpr::Table(_) => Ok(false),
        }
    }

    fn rewrite_select(
        &self,
        select: &mut Select,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let scope = self.scope(&select.from)?;
        let mut changed = false;
        for table in &mut select.from {
            for join in &mut table.joins {
                if let Some(constraint) = join_condition(&mut join.join_operator) {
                    changed |= self.rewrite_selection(constraint, &scope, params)?;
                }
            }
        }
        // Derived tables carry their own FROM, so they are rewritten against
        // their own scope rather than this one.
        for table in &mut select.from {
            for factor in std::iter::once(&mut table.relation)
                .chain(table.joins.iter_mut().map(|join| &mut join.relation))
            {
                if let TableFactor::Derived { subquery, .. } = factor {
                    changed |= self.rewrite_query(subquery, params)?;
                }
            }
        }
        for predicate in [select.selection.as_mut(), select.having.as_mut()].into_iter().flatten() {
            changed |= self.rewrite_selection(predicate, &scope, params)?;
        }
        Ok(changed)
    }

    /// Collects the protected tables visible to a predicate, with their
    /// aliases, so column references can be resolved.
    fn scope(&self, from: &[TableWithJoins]) -> Result<TableScope<'_>, Rejection> {
        let mut tables = Vec::new();
        for table_with_joins in from {
            let factors = std::iter::once(&table_with_joins.relation)
                .chain(table_with_joins.joins.iter().map(|join| &join.relation));
            for factor in factors {
                let TableFactor::Table { name, alias, .. } = factor else { continue };
                let Some(columns) = self.table(name)? else { continue };
                tables.push(ScopedTable {
                    alias: alias.as_ref().map(|alias| normalize(&alias.name)),
                    name: name.0.iter().map(normalize).collect(),
                    columns,
                });
            }
        }
        Ok(TableScope { tables })
    }

    /// Rewrites the equality shapes that a blind index can answer, and turns
    /// everything else that mentions a searchable column into an
    /// [`Unprotected`] site — an unrewritten predicate matches no row, and
    /// "no rows" is indistinguishable from "no such user".
    fn rewrite_selection(
        &self,
        expr: &mut Expr,
        scope: &TableScope<'_>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        use sqlparser::ast::BinaryOperator;
        match expr {
            Expr::BinaryOp { left, op: BinaryOperator::Eq, right } => {
                if let Some(transform) = column_ref(scope, left).cloned() {
                    self.rewrite_equality(left, right, &transform, params)
                } else if let Some(transform) = column_ref(scope, right).cloned() {
                    self.rewrite_equality(right, left, &transform, params)
                } else {
                    self.unsupported_predicate(expr, scope)
                }
            }
            Expr::BinaryOp { left, op: BinaryOperator::And | BinaryOperator::Or, right } => {
                let left = self.rewrite_selection(left, scope, params)?;
                let right = self.rewrite_selection(right, scope, params)?;
                Ok(left | right)
            }
            Expr::Nested(inner) => self.rewrite_selection(inner, scope, params),
            Expr::UnaryOp { op: sqlparser::ast::UnaryOperator::Not, expr: inner } => {
                self.rewrite_selection(inner, scope, params)
            }
            Expr::InList { expr: column, list, .. } => {
                self.rewrite_in_list(column, list, scope, params)
            }
            Expr::AnyOp { left, compare_op: BinaryOperator::Eq, right, .. } => {
                if let Expr::Array(array) = right.as_mut() {
                    return self.rewrite_in_list(left, &mut array.elem, scope, params);
                }
                // `= ANY($1)` is one bound array parameter: the elements only
                // exist at Bind time, so the index is applied there.
                if let Some((index, transform)) = array_parameter(left, right, scope) {
                    let column: Arc<str> = column_name(left).unwrap_or_default().into();
                    params.record(index, ParamAction::SearchIndexArray { transform, column })?;
                    let operand = std::mem::replace(left.as_mut(), Expr::Value(Value::Null));
                    *left.as_mut() = index_prefix(operand);
                    return Ok(true);
                }
                self.unsupported_predicate(expr, scope)
            }
            _ => self.unsupported_predicate(expr, scope),
        }
    }

    /// `col IN (a, b)` and `col = ANY(ARRAY[a, b])` become an index-prefix
    /// match against the indexed values. Either every element is indexable or
    /// none is rewritten: a mixed predicate compares some values against the
    /// index and others against the stored form.
    fn rewrite_in_list(
        &self,
        column: &mut Expr,
        list: &mut [Expr],
        scope: &TableScope<'_>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let Some(transform) = column_ref(scope, column).cloned() else { return Ok(false) };
        if !transform.supports_search() {
            return Ok(false);
        }
        let indexable = !list.is_empty()
            && list.iter().all(|value| match unwrap_casts(value) {
                Expr::Value(Value::Placeholder(placeholder)) => {
                    placeholder_index(placeholder).is_some()
                }
                other => literal_plaintext(other, transform.wire()).is_some(),
            });
        if !indexable {
            let column = column_name(column).unwrap_or_default();
            self.unprotected(&Unprotected::Predicate { column, shape: "IN list" })?;
            return Ok(false);
        }
        for value in list.iter_mut() {
            index_value(value, &transform, params)?;
        }
        *column = index_prefix(std::mem::replace(column, Expr::Value(Value::Null)));
        Ok(true)
    }

    /// Turns `col = <value>` into `substring(col from 1 for 32) = <index>`.
    /// Literals get the index inline; placeholders are indexed at Bind time.
    fn rewrite_equality(
        &self,
        column: &mut Expr,
        value: &mut Expr,
        transform: &Arc<dyn FieldTransform>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        if !transform.supports_search() {
            return Ok(false);
        }
        let indexable = match unwrap_casts(value) {
            Expr::Value(Value::Placeholder(placeholder)) => {
                placeholder_index(placeholder).is_some()
            }
            other => literal_plaintext(other, transform.wire()).is_some(),
        };
        if !indexable {
            let column = column_name(column).unwrap_or_default();
            self.unprotected(&Unprotected::Predicate { column, shape: expr_shape(value) })?;
            return Ok(false);
        }
        index_value(value, transform, params)?;
        *column = index_prefix(std::mem::replace(column, Expr::Value(Value::Null)));
        Ok(true)
    }

    /// A predicate the rewriter cannot turn into an index match. Only worth a
    /// signal when it actually mentions a searchable column — otherwise it is
    /// ordinary SQL the proxy has no business commenting on.
    fn unsupported_predicate(
        &self,
        expr: &Expr,
        scope: &TableScope<'_>,
    ) -> Result<bool, Rejection> {
        let Some(column) = searchable_operand(expr, scope) else { return Ok(false) };
        self.unprotected(&Unprotected::Predicate { column, shape: expr_shape(expr) })?;
        Ok(false)
    }

    /// Seals one literal in place, or records the placeholder for Bind time.
    /// Returns whether the statement text changed.
    fn seal_expr(
        &self,
        expr: &mut Expr,
        transform: &Arc<dyn FieldTransform>,
        column: &str,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        match unwrap_casts(expr) {
            Expr::Value(Value::Placeholder(placeholder)) => {
                if let Some(index) = placeholder_index(placeholder) {
                    params.record(index, ParamAction::Seal(transform.clone()))?;
                }
                return Ok(false);
            }
            Expr::Value(Value::Null) => return Ok(false),
            _ => {}
        }
        let Some(plaintext) = literal_plaintext(expr, transform.wire()) else {
            self.unprotected(&Unprotected::UnsupportedValue { column, shape: expr_shape(expr) })?;
            return Ok(false);
        };
        let sealed = transform.seal(&plaintext).map_err(Error::Wire)?;
        let literal = match transform.wire() {
            WireForm::Bytea => format!("\\x{}", hex::encode(sealed)),
            WireForm::Text => String::from_utf8_lossy(&sealed).into_owned(),
        };
        *expr = Expr::Value(Value::SingleQuotedString(literal));
        Ok(true)
    }
}

/// Parses one SQL text, retrying once with a statement terminator.
///
/// `COPY ... FROM STDIN` is the reason. sqlparser reads the TSV payload that
/// follows it in a script, so it wants either the data and its `\.` terminator
/// or a `;`. On the wire there is neither — the payload arrives later as
/// `CopyData` frames — so the statement fails to parse and `COPY` would only
/// ever be seen as unparseable SQL, with a warning naming the wrong problem.
/// The retry costs one extra parse on text that already failed.
fn parse_sql(text: &str) -> Result<Vec<Statement>, ParserError> {
    let dialect = PostgreSqlDialect {};
    let error = match Parser::parse_sql(&dialect, text) {
        Ok(statements) => return Ok(statements),
        Err(error) => error,
    };
    Parser::parse_sql(&dialect, &format!("{text};")).map_err(|_| error)
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

/// The `ON` condition of a join, when it has one.
fn join_condition(operator: &mut JoinOperator) -> Option<&mut Expr> {
    let constraint = match operator {
        JoinOperator::Inner(constraint)
        | JoinOperator::LeftOuter(constraint)
        | JoinOperator::RightOuter(constraint)
        | JoinOperator::FullOuter(constraint)
        | JoinOperator::Semi(constraint)
        | JoinOperator::LeftSemi(constraint)
        | JoinOperator::RightSemi(constraint)
        | JoinOperator::Anti(constraint)
        | JoinOperator::LeftAnti(constraint)
        | JoinOperator::RightAnti(constraint)
        | JoinOperator::AsOf { constraint, .. } => constraint,
        JoinOperator::CrossJoin | JoinOperator::CrossApply | JoinOperator::OuterApply => {
            return None
        }
    };
    match constraint {
        JoinConstraint::On(expr) => Some(expr),
        JoinConstraint::Using(_) | JoinConstraint::Natural | JoinConstraint::None => None,
    }
}

/// Whether a `SET search_path` still leaves `public` as the schema an
/// unqualified name resolves to. `"$user", public` is PostgreSQL's own
/// default and stays trusted; anything else in front of `public` does not,
/// because a bare name may resolve there instead.
fn is_default_search_path(values: &[Expr]) -> bool {
    let names: Vec<String> = values.iter().filter_map(setting_name).collect();
    if names.len() != values.len() {
        return false;
    }
    names.iter().all(|name| name == "public" || name == "$user")
        && names.iter().any(|n| n == "public")
}

fn setting_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Identifier(ident) => Some(normalize(ident)),
        Expr::Value(Value::SingleQuotedString(value) | Value::DoubleQuotedString(value)) => {
            Some(value.clone())
        }
        _ => None,
    }
}

struct ScopedTable<'a> {
    alias: Option<String>,
    /// The table's name parts, normalized — owned so the scope does not
    /// borrow the statement it was built from, which the rewrite mutates.
    name: Vec<String>,
    columns: &'a Columns,
}

/// Protected tables a predicate can reference.
struct TableScope<'a> {
    tables: Vec<ScopedTable<'a>>,
}

impl TableScope<'_> {
    /// Resolves a (possibly qualified) column reference to its transform.
    /// Unqualified names matching more than one protected table are skipped —
    /// ambiguity must not guess.
    fn resolve(&self, idents: &[Ident]) -> Option<&Arc<dyn FieldTransform>> {
        let (column, qualifiers) = idents.split_last()?;
        let column = normalize(column);
        let matches: Vec<_> = self
            .tables
            .iter()
            .filter(|table| table.matches(qualifiers))
            .filter_map(|table| table.columns.get(&column))
            .collect();
        match matches.as_slice() {
            [transform] => Some(transform),
            [] => None,
            _ => {
                tracing::warn!(column, "ambiguous column reference; equality not rewritten");
                None
            }
        }
    }
}

impl ScopedTable<'_> {
    fn matches(&self, qualifiers: &[Ident]) -> bool {
        match qualifiers {
            [] => true,
            [qualifier] => {
                let qualifier = normalize(qualifier);
                self.alias.as_deref() == Some(qualifier.as_str())
                    || self.name.last().is_some_and(|last| *last == qualifier)
            }
            _ => {
                // schema.table (or longer): compare the trailing parts.
                let want: Vec<String> = qualifiers.iter().map(normalize).collect();
                self.name.len() >= want.len()
                    && self.name[self.name.len() - want.len()..] == want[..]
            }
        }
    }
}

fn column_ref<'a>(scope: &'a TableScope<'_>, expr: &Expr) -> Option<&'a Arc<dyn FieldTransform>> {
    match expr {
        Expr::Identifier(ident) => scope.resolve(std::slice::from_ref(ident)),
        Expr::CompoundIdentifier(idents) => scope.resolve(idents),
        _ => None,
    }
}

fn column_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Identifier(ident) => Some(normalize(ident)),
        Expr::CompoundIdentifier(idents) => idents.last().map(normalize),
        _ => None,
    }
}

/// The searchable column an unhandled predicate is about, if any. Only the
/// operands of the predicate are inspected — a searchable column buried in a
/// subquery belongs to that subquery's own traversal.
fn searchable_operand(expr: &Expr, scope: &TableScope<'_>) -> Option<String> {
    let operands: [&Expr; 2] = match expr {
        Expr::BinaryOp { left, right, .. } => [left, right],
        Expr::AnyOp { left, right, .. } | Expr::AllOp { left, right, .. } => [left, right],
        Expr::InList { expr, .. }
        | Expr::InSubquery { expr, .. }
        | Expr::Between { expr, .. }
        | Expr::Like { expr, .. }
        | Expr::ILike { expr, .. }
        | Expr::SimilarTo { expr, .. }
        | Expr::IsNull(expr)
        | Expr::IsNotNull(expr)
        | Expr::IsDistinctFrom(expr, _)
        | Expr::IsNotDistinctFrom(expr, _) => [expr, expr],
        _ => return None,
    };
    operands
        .into_iter()
        .find(|operand| column_ref(scope, operand).is_some_and(|t| t.supports_search()))
        .and_then(column_name)
}

/// The AST discriminant of an expression — its *shape*, never its value.
/// Logging the expression itself would put the plaintext bound to a protected
/// column straight into the log.
fn expr_shape(expr: &Expr) -> &'static str {
    match expr {
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => "column reference",
        Expr::Value(_) => "literal",
        Expr::Function(_) => "function call",
        Expr::Cast { .. } => "cast",
        Expr::BinaryOp { .. } => "binary operator",
        Expr::UnaryOp { .. } => "unary operator",
        Expr::Case { .. } => "CASE",
        Expr::Subquery(_) => "subquery",
        Expr::InSubquery { .. } => "IN subquery",
        Expr::InList { .. } => "IN list",
        Expr::AnyOp { .. } => "= ANY",
        Expr::AllOp { .. } => "= ALL",
        Expr::Like { .. } | Expr::ILike { .. } | Expr::SimilarTo { .. } => "pattern match",
        Expr::Between { .. } => "BETWEEN",
        Expr::IsNull(_) | Expr::IsNotNull(_) => "IS NULL",
        Expr::IsDistinctFrom(_, _) | Expr::IsNotDistinctFrom(_, _) => "IS DISTINCT FROM",
        Expr::Array(_) => "array",
        Expr::TypedString { .. } => "typed literal",
        Expr::Nested(_) => "parenthesized expression",
        _ => "unsupported expression",
    }
}

/// `substring(col from 1 for 32)` — the stored blind-index prefix.
fn index_prefix(column: Expr) -> Expr {
    let number = |n: &str| Box::new(Expr::Value(Value::Number(n.into(), false)));
    Expr::Substring {
        expr: Box::new(column),
        substring_from: Some(number("1")),
        substring_for: Some(number(&dbsec_core::blind_index::BLIND_INDEX_LEN.to_string())),
        special: false,
    }
}

/// Replaces one compared value with its blind index: inline for a literal,
/// recorded for Bind time for a placeholder. Callers check first that the
/// value is one of those two.
fn index_value(
    value: &mut Expr,
    transform: &Arc<dyn FieldTransform>,
    params: &mut ParamTransforms,
) -> Result<(), Error> {
    if let Expr::Value(Value::Placeholder(placeholder)) = unwrap_casts(value) {
        let Some(index) = placeholder_index(placeholder) else {
            return Err(Error::Wire(dbsec_core::Error::Malformed));
        };
        params.record(index, ParamAction::SearchIndex(transform.clone()))?;
        return Ok(());
    }
    let Some(plaintext) = literal_plaintext(value, transform.wire()) else {
        return Err(Error::Wire(dbsec_core::Error::Malformed));
    };
    let Some(token) = transform.search_index(&plaintext)? else {
        return Err(Error::Wire(dbsec_core::Error::Malformed));
    };
    *value = Expr::Value(Value::SingleQuotedString(format!("\\x{}", hex::encode(token))));
    Ok(())
}

/// One transformed Bind parameter, in the format the parameter arrived in.
/// Text-shaped stored forms (FPE digits, hex tokens) are the same bytes in
/// either format; a BYTEA form in a text-format parameter is `\x` hex.
fn encode_param(value: Vec<u8>, wire: WireForm, binary: bool) -> Vec<u8> {
    match wire {
        WireForm::Text => value,
        WireForm::Bytea if binary => value,
        WireForm::Bytea => format!("\\x{}", hex::encode(value)).into_bytes(),
    }
}

/// PostgreSQL's `bytea` type OID. The blind index prefix is BYTEA whatever the
/// column's own stored form is, so a re-encoded `= ANY($n)` array is a
/// `bytea[]` — the same element type the `ARRAY[...]` rewrite produces.
const BYTEA_OID: i32 = 17;

/// Element type OIDs whose binary form *is* the plaintext bytes, and which can
/// therefore be blind-indexed element by element: bytea, and the string types.
/// Anything else — an int, a timestamp, a composite — is not a value this
/// proxy ever sealed, so its array is left alone rather than turned into a
/// query that matches the wrong rows.
const INDEXABLE_ELEMENT_OIDS: [i32; 6] = [
    BYTEA_OID, // bytea
    19,        // name
    25,        // text
    705,       // unknown
    1042,      // bpchar
    1043,      // varchar
];

/// Most elements one `= ANY($n)` array may carry. A Bind body is bounded at
/// 1 GiB, which is room for hundreds of millions of empty elements and one
/// HMAC each; this caps the work a single parameter can ask for (SEC-33).
/// Real multi-value lookups are orders of magnitude below it, and an array
/// over the cap falls back to the refusal rather than being indexed.
const MAX_ARRAY_ELEMENTS: usize = 65_536;

/// One decoded `= ANY($n)` array parameter.
struct BoundArray {
    /// Element plaintexts, `None` for a NULL element.
    elements: Vec<Option<Vec<u8>>>,
    /// The array's lower bound, preserved so the re-encoded array is the same
    /// array with different values in it.
    lower_bound: i32,
}

/// Replaces every element of a bound `= ANY($n)` array with its blind index
/// and re-encodes it as `bytea[]` in the parameter's own format, which is what
/// makes `substring(col from 1 for 32) = ANY($n)` match the stored rows.
///
/// `Ok(None)` is the fallback for anything this cannot do faithfully — a
/// parameter that is not a one-dimensional array, an element type that is not
/// a plaintext the proxy seals, an array over [`MAX_ARRAY_ELEMENTS`] — and the
/// caller turns it into the same [`Unprotected::Predicate`] signal the SQL
/// rewrite raises. Nothing partially indexed is ever produced: half the
/// elements matching the index and half the stored form is a *valid* query
/// that silently returns the wrong rows.
///
/// A NULL element stays NULL: `x = ANY(...)` is never true for one, so it
/// changes no row either way.
fn index_array(
    value: &[u8],
    binary: bool,
    transform: &Arc<dyn FieldTransform>,
) -> Result<Option<Vec<u8>>, Error> {
    let decoded = if binary {
        decode_binary_array(value)
    } else {
        decode_text_array(value, transform.wire())
    };
    let Some(array) = decoded else { return Ok(None) };
    let mut indexed = Vec::with_capacity(array.elements.len());
    for element in &array.elements {
        let Some(plaintext) = element else {
            indexed.push(None);
            continue;
        };
        let Some(token) = transform.search_index(plaintext)? else { return Ok(None) };
        indexed.push(Some(token));
    }
    Ok(if binary {
        encode_binary_array(&indexed, array.lower_bound)
    } else {
        Some(encode_text_array(&indexed))
    })
}

/// Decodes the binary array format: `ndim | flags | element oid`, then one
/// `length | lower bound` pair per dimension, then each element as
/// `length | bytes` with `-1` for NULL. Every field is checked against what is
/// actually there — this is client-supplied and the only thing that has
/// validated it so far is nothing (SEC-11).
fn decode_binary_array(mut raw: &[u8]) -> Option<BoundArray> {
    let ndim = take_i32(&mut raw)?;
    let _flags = take_i32(&mut raw)?;
    let element_oid = take_i32(&mut raw)?;
    if !INDEXABLE_ELEMENT_OIDS.contains(&element_oid) {
        return None;
    }
    match ndim {
        // No dimensions at all is the canonical empty array.
        0 => return raw.is_empty().then(|| BoundArray { elements: Vec::new(), lower_bound: 1 }),
        1 => {}
        _ => return None,
    }
    let count = take_i32(&mut raw)?;
    let lower_bound = take_i32(&mut raw)?;
    let count = usize::try_from(count).ok().filter(|count| *count <= MAX_ARRAY_ELEMENTS)?;
    let mut elements = Vec::new();
    for _ in 0..count {
        let size = take_i32(&mut raw)?;
        if size == -1 {
            elements.push(None);
            continue;
        }
        let size = usize::try_from(size).ok()?;
        if raw.len() < size {
            return None;
        }
        let (element, rest) = raw.split_at(size);
        elements.push(Some(element.to_vec()));
        raw = rest;
    }
    // Trailing bytes mean the message was not the array it claimed to be.
    raw.is_empty().then_some(BoundArray { elements, lower_bound })
}

/// Takes one big-endian `i32`, or `None` when fewer than four bytes are left.
fn take_i32(buf: &mut &[u8]) -> Option<i32> {
    if buf.len() < 4 {
        return None;
    }
    let (head, rest) = buf.split_at(4);
    *buf = rest;
    Some(i32::from_be_bytes(head.try_into().ok()?))
}

/// Decodes the text array format: `{a,"b c",NULL}`, where an element may be
/// double-quoted and a quoted element escapes `"` and `\` with a backslash.
/// Only a flat, one-dimensional array is accepted — a nested array or an
/// explicit `[1:2]=` dimension prefix falls back rather than being guessed at.
fn decode_text_array(raw: &[u8], wire: WireForm) -> Option<BoundArray> {
    let text = std::str::from_utf8(raw).ok()?.trim();
    let body = text.strip_prefix('{')?.strip_suffix('}')?;
    let mut elements: Vec<Option<Vec<u8>>> = Vec::new();
    if body.trim().is_empty() {
        return Some(BoundArray { elements, lower_bound: 1 });
    }
    let bytes = body.as_bytes();
    let mut at = 0;
    loop {
        while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        let element = if bytes.get(at) == Some(&b'"') {
            at += 1;
            let mut value = Vec::new();
            loop {
                match *bytes.get(at)? {
                    b'\\' => {
                        value.push(*bytes.get(at + 1)?);
                        at += 2;
                    }
                    b'"' => {
                        at += 1;
                        break;
                    }
                    byte => {
                        value.push(byte);
                        at += 1;
                    }
                }
            }
            Some(String::from_utf8(value).ok()?)
        } else {
            let start = at;
            while bytes.get(at).is_some_and(|byte| *byte != b',') {
                at += 1;
            }
            let unquoted = body.get(start..at)?.trim_end();
            // A brace here is a nested array, which this does not handle.
            if unquoted.contains(['{', '}']) {
                return None;
            }
            (!unquoted.eq_ignore_ascii_case("null")).then(|| unquoted.to_owned())
        };
        elements.push(element.map(|text| text_plaintext(&text, wire)));
        if elements.len() > MAX_ARRAY_ELEMENTS {
            return None;
        }
        while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        match bytes.get(at) {
            None => break,
            Some(b',') => at += 1,
            Some(_) => return None,
        }
    }
    Some(BoundArray { elements, lower_bound: 1 })
}

/// Re-encodes indexed elements in the binary array format. `None` only when
/// the element count does not fit the protocol's `i32` — impossible under
/// [`MAX_ARRAY_ELEMENTS`], and checked rather than cast so it stays impossible
/// if that cap ever moves (SEC-15).
fn encode_binary_array(elements: &[Option<Vec<u8>>], lower_bound: i32) -> Option<Vec<u8>> {
    let count = i32::try_from(elements.len()).ok()?;
    let has_null = elements.iter().any(Option::is_none);
    let payload: usize = elements.iter().flatten().map(Vec::len).sum();
    let mut out = Vec::with_capacity(20 + elements.len() * 4 + payload);
    out.extend_from_slice(&if elements.is_empty() { 0i32 } else { 1i32 }.to_be_bytes());
    out.extend_from_slice(&i32::from(has_null).to_be_bytes());
    out.extend_from_slice(&BYTEA_OID.to_be_bytes());
    if elements.is_empty() {
        return Some(out);
    }
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&lower_bound.to_be_bytes());
    for element in elements {
        match element {
            None => out.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(token) => {
                let size = i32::try_from(token.len()).ok()?;
                out.extend_from_slice(&size.to_be_bytes());
                out.extend_from_slice(token);
            }
        }
    }
    Some(out)
}

/// Re-encodes indexed elements as an array literal. Each element is bytea's
/// `\x` hex input syntax, quoted — and inside a quoted array element the
/// backslash itself has to be escaped, or the array parser eats it.
fn encode_text_array(elements: &[Option<Vec<u8>>]) -> Vec<u8> {
    let mut out = String::from("{");
    for (position, element) in elements.iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        match element {
            None => out.push_str("NULL"),
            Some(token) => {
                out.push_str("\"\\\\x");
                out.push_str(&hex::encode(token));
                out.push('"');
            }
        }
    }
    out.push('}');
    out.into_bytes()
}

/// The parameter index and transform behind `col = ANY($n)`, when `col` is a
/// searchable column and the right operand is one bound array parameter.
/// `None` for every other shape — `= ANY(SELECT ...)`, an array expression, a
/// non-searchable column — which the caller signals as an unsupported
/// predicate exactly as before.
fn array_parameter(
    column: &Expr,
    array: &Expr,
    scope: &TableScope<'_>,
) -> Option<(usize, Arc<dyn FieldTransform>)> {
    let transform = column_ref(scope, column).filter(|t| t.supports_search())?.clone();
    let Expr::Value(Value::Placeholder(placeholder)) = unwrap_casts(array) else { return None };
    Some((placeholder_index(placeholder)?, transform))
}

/// Splits a Describe or Close body into its target and name — both messages
/// share the shape `u8 kind | cstr name`. A kind byte that is neither `'S'`
/// (statement) nor `'P'` (portal) is a protocol violation the relay must not
/// guess at: carrying on would leave the read path's expectations misaligned
/// with what the server is about to answer.
fn describe_target(body: &[u8]) -> Result<(Target, &[u8]), Error> {
    let [kind, rest @ ..] = body else {
        return Err(Error::Wire(dbsec_core::Error::Malformed));
    };
    let target = match kind {
        b'S' => Target::Statement,
        b'P' => Target::Portal,
        _ => return Err(Error::Wire(dbsec_core::Error::Malformed)),
    };
    let mut rest = rest;
    let name = pgwire::take_cstr(&mut rest)?;
    Ok((target, name))
}

/// The zero-based parameter index a `$n` placeholder refers to, or `None` when
/// it names no bindable parameter.
///
/// `n` is client-supplied SQL, so the subtraction is checked: PostgreSQL
/// numbers parameters from 1 and `$0` is not a parameter at all. Subtracting
/// unchecked panicked the session task in debug builds and wrapped to
/// `usize::MAX` in release, where the rewrite went ahead against an index no
/// Bind can ever fill (SEC-15).
fn placeholder_index(placeholder: &str) -> Option<usize> {
    placeholder.strip_prefix('$').and_then(|n| n.parse::<usize>().ok())?.checked_sub(1)
}

/// Peels the casts and parentheses drivers wrap literals in — psycopg's
/// client-side binding renders every bytes parameter as `'\x…'::bytea` — so
/// the value underneath can be recognised.
fn unwrap_casts(expr: &Expr) -> &Expr {
    match expr {
        Expr::Cast { expr, .. } | Expr::Nested(expr) => unwrap_casts(expr),
        other => other,
    }
}

/// The plaintext a literal expression stands for, or `None` when it is not a
/// literal at all. For BYTEA-form columns a `\x`-prefixed string is
/// Postgres' hex input syntax, so it denotes the bytes it encodes rather than
/// its own characters — sealing it verbatim would round-trip the hex text.
fn literal_plaintext(expr: &Expr, wire: WireForm) -> Option<Vec<u8>> {
    match unwrap_casts(expr) {
        Expr::Value(Value::SingleQuotedString(s)) => Some(text_plaintext(s, wire)),
        Expr::Value(Value::Number(n, _)) => Some(n.as_bytes().to_vec()),
        _ => None,
    }
}

/// The plaintext a piece of text stands for — shared by SQL literals and text
/// format array elements, which read `\x` the same way.
fn text_plaintext(text: &str, wire: WireForm) -> Vec<u8> {
    match wire {
        WireForm::Bytea => text
            .strip_prefix("\\x")
            .and_then(|hex| hex::decode(hex).ok())
            .unwrap_or_else(|| text.as_bytes().to_vec()),
        WireForm::Text => text.as_bytes().to_vec(),
    }
}

/// What one SQL text produced: a rewritten statement (when literals were
/// sealed) and the placeholder positions to seal at Bind time.
struct RewriteOutcome {
    rewritten: Option<String>,
    params: ParamTransforms,
}

impl RewriteOutcome {
    fn passthrough() -> Self {
        Self { rewritten: None, params: ParamTransforms::default() }
    }
}

/// Rebuilds the SQL text, re-rendering only the statements that changed and
/// keeping everything else — the untouched statements, the separators, the
/// comments around them — exactly as the client wrote it.
fn reassemble(sql: &str, statements: &[Statement], changed: &[bool]) -> Result<String, Error> {
    let Some(ranges) = statement_ranges(sql).filter(|ranges| ranges.len() == statements.len())
    else {
        // The source text could not be lined up with the parsed statements,
        // so there is no original text to preserve. Every statement is
        // rendered, and every rendering is validated below.
        tracing::warn!(
            statements = statements.len(),
            "could not map statements back to their source text; re-rendering all of them"
        );
        let rendered: Result<Vec<String>, Error> =
            statements.iter().map(render_validated).collect();
        return Ok(rendered?.join("; "));
    };
    let mut out = String::with_capacity(sql.len());
    let mut cursor = 0;
    for ((range, statement), changed) in ranges.iter().zip(statements).zip(changed) {
        out.push_str(&sql[cursor..range.start]);
        if *changed {
            out.push_str(&render_validated(statement)?);
        } else {
            out.push_str(&sql[range.clone()]);
        }
        cursor = range.end;
    }
    out.push_str(&sql[cursor..]);
    Ok(out)
}

/// Renders a rewritten statement and checks that it means what the AST says:
/// re-parse it and compare. sqlparser's `Display` is not contractually a
/// round-trip, and this is the one path where the proxy hands the server SQL
/// the client never wrote — a divergence has to fail the session, because the
/// alternative is executing a valid statement with different semantics.
fn render_validated(statement: &Statement) -> Result<String, Error> {
    let rendered = statement.to_string();
    match parse_sql(&rendered) {
        Ok(reparsed) if reparsed.len() == 1 && reparsed[0] == *statement => Ok(rendered),
        _ => Err(Error::RewriteDiverged),
    }
}

/// The byte ranges of the top-level statements in `sql`, trimmed of
/// surrounding whitespace. `None` when the text cannot be split with
/// confidence — an unterminated literal, identifier, dollar-quoted body or
/// block comment — in which case the caller does not try to preserve it.
fn statement_ranges(sql: &str) -> Option<Vec<Range<usize>>> {
    let bytes = sql.as_bytes();
    let mut ranges: Vec<Range<usize>> = Vec::new();
    let mut start = 0;
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'\'' | b'"' => at = skip_quoted(bytes, at)?,
            b'$' => at = skip_dollar_quoted(bytes, at)?,
            b'-' if bytes.get(at + 1) == Some(&b'-') => {
                at = bytes[at..].iter().position(|&b| b == b'\n').map_or(bytes.len(), |n| at + n);
            }
            b'/' if bytes.get(at + 1) == Some(&b'*') => at = skip_block_comment(bytes, at)?,
            b';' => {
                push_statement(&mut ranges, sql, start..at);
                at += 1;
                start = at;
            }
            _ => at += 1,
        }
    }
    push_statement(&mut ranges, sql, start..bytes.len());
    Some(ranges)
}

fn push_statement(ranges: &mut Vec<Range<usize>>, sql: &str, range: Range<usize>) {
    let trimmed = sql[range.clone()].trim();
    if trimmed.is_empty() {
        return;
    }
    let start = range.start + (sql[range.clone()].len() - sql[range.clone()].trim_start().len());
    ranges.push(start..start + trimmed.len());
}

/// Skips a `'...'` literal or a `"..."` identifier, both of which escape the
/// closing character by doubling it. `E'...'` also escapes with backslashes.
fn skip_quoted(bytes: &[u8], start: usize) -> Option<usize> {
    let quote = bytes[start];
    let backslash_escapes = quote == b'\''
        && start > 0
        && matches!(bytes[start - 1], b'e' | b'E')
        && (start == 1 || !is_ident_byte(bytes[start - 2]));
    let mut at = start + 1;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' if backslash_escapes => at += 2,
            b if b == quote => {
                if bytes.get(at + 1) == Some(&quote) {
                    at += 2;
                } else {
                    return Some(at + 1);
                }
            }
            _ => at += 1,
        }
    }
    None
}

/// Skips a `$tag$ ... $tag$` body. A `$` that does not open one — a `$1`
/// placeholder, say — just advances one byte.
fn skip_dollar_quoted(bytes: &[u8], start: usize) -> Option<usize> {
    let tag_end =
        bytes[start + 1..].iter().position(|&b| b == b'$').map(|n| start + 1 + n).filter(|end| {
            bytes[start + 1..*end].iter().all(|&b| is_ident_byte(b) && !b.is_ascii_digit())
        });
    let Some(tag_end) = tag_end else { return Some(start + 1) };
    let tag = &bytes[start..=tag_end];
    let mut at = tag_end + 1;
    while at + tag.len() <= bytes.len() {
        if &bytes[at..at + tag.len()] == tag {
            return Some(at + tag.len());
        }
        at += 1;
    }
    None
}

/// Skips a `/* ... */` comment, which PostgreSQL allows to nest.
fn skip_block_comment(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut at = start;
    while at + 1 < bytes.len() {
        match (bytes[at], bytes[at + 1]) {
            (b'/', b'*') => {
                depth += 1;
                at += 2;
            }
            (b'*', b'/') => {
                depth -= 1;
                at += 2;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => at += 1,
        }
    }
    None
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Every place a write to a protected column is not rewritten, or a predicate
/// over a searchable column is not turned into an index match. Each one is a
/// documented hole in the "never at rest in plaintext" invariant, which is
/// why they are enumerated here rather than inlined at the call sites.
enum Unprotected<'a> {
    /// The Query body is not valid UTF-8, so it cannot be parsed at all.
    NonUtf8,
    /// sqlparser could not parse the SQL.
    Unparseable(&'a ParserError),
    /// `INSERT` without a column list: values cannot be matched to columns.
    NoColumnList(&'a ObjectName),
    /// `INSERT ... SELECT`: the values are rows, not literals.
    InsertFromSelect(&'a ObjectName),
    /// `COPY`, whose payload is a `CopyData` stream the proxy does not parse.
    Copy { table: &'a ObjectName, to: bool },
    /// A statement shape that writes a protected table but is not rewritten.
    Unsupported { table: &'a ObjectName, shape: &'static str },
    /// A non-literal expression assigned to a protected column.
    UnsupportedValue { column: &'a str, shape: &'static str },
    /// A predicate over a searchable column that no index match can express.
    Predicate { column: String, shape: &'static str },
    /// `SET search_path` moved off the schema the catalog resolves against.
    SearchPathChanged,
    /// An unqualified name that may be a protected table, in a session whose
    /// `search_path` no longer says which schema it resolves to.
    SearchPath(&'a ObjectName),
}

impl Unprotected<'_> {
    /// Emits the site's warning. The wording of the six original passthrough
    /// sites is unchanged so log-based alerting keeps matching; only the
    /// fields that carried plaintext (the bound expression, the parser's
    /// message) are gone, replaced by the shape and the parser error kind.
    fn warn(&self) {
        match self {
            Self::NonUtf8 => {
                tracing::warn!("query is not valid UTF-8; passing through unencrypted");
            }
            Self::Unparseable(error) => {
                tracing::warn!(
                    error_kind = parser_error_kind(error),
                    "unparseable SQL; passing through unencrypted"
                );
            }
            Self::NoColumnList(table) => tracing::warn!(
                table = %table,
                "INSERT without a column list on a protected table; passing through unencrypted"
            ),
            Self::InsertFromSelect(table) => tracing::warn!(
                table = %table,
                "INSERT ... SELECT into a protected table; passing through unencrypted"
            ),
            Self::Copy { table, to } => tracing::warn!(
                table = %table,
                direction = if *to { "to" } else { "from" },
                "COPY on a protected table is not encrypted by the proxy"
            ),
            Self::Unsupported { table, shape } => tracing::warn!(
                table = %table,
                shape,
                "statement writes a protected table but is not rewritten; passing through unencrypted"
            ),
            Self::UnsupportedValue { column, shape } => tracing::warn!(
                column,
                shape,
                "unsupported expression for a protected column; passing through unencrypted"
            ),
            Self::Predicate { column, shape } => tracing::warn!(
                column,
                shape,
                "unsupported predicate for a searchable column; it will match no rows"
            ),
            Self::SearchPathChanged => tracing::warn!(
                "session changed search_path; unqualified names no longer resolve to the \
                 configured schema"
            ),
            Self::SearchPath(table) => tracing::warn!(
                table = %table,
                "unqualified name may be a protected table under this session's search_path; \
                 passing through unencrypted"
            ),
        }
    }

    /// The ErrorResponse text for the refusal. Identifiers and shapes only —
    /// this goes to the client, but it also lands in its logs.
    fn message(&self) -> String {
        let detail = match self {
            Self::NonUtf8 => {
                "the query is not valid UTF-8, so protected columns cannot be found in it"
                    .to_owned()
            }
            Self::Unparseable(error) => format!(
                "the SQL could not be parsed ({}), so protected columns cannot be found in it",
                parser_error_kind(error)
            ),
            Self::NoColumnList(table) => {
                format!("INSERT into protected table {table} needs an explicit column list")
            }
            Self::InsertFromSelect(table) => {
                format!("INSERT ... SELECT into protected table {table} cannot be encrypted")
            }
            Self::Copy { table, to } => format!(
                "COPY {} protected table {table} bypasses the proxy's encryption",
                if *to { "from" } else { "into" }
            ),
            Self::Unsupported { table, shape } => {
                format!("{shape} writing protected table {table} cannot be encrypted")
            }
            Self::UnsupportedValue { column, shape } => format!(
                "protected column {column} was assigned a {shape}, which cannot be encrypted"
            ),
            Self::Predicate { column, shape } => format!(
                "searchable column {column} was used in a {shape}, which cannot be matched \
                 against its blind index"
            ),
            Self::SearchPathChanged => {
                "changing search_path leaves unqualified names resolving to an unknown schema"
                    .to_owned()
            }
            Self::SearchPath(table) => format!(
                "{table} is unqualified and this session changed search_path, so it cannot be \
                 resolved to a protected table"
            ),
        };
        format!("dbsec refused this statement: {detail} (on_unprotected = \"reject\")")
    }
}

/// The parser error's variant. Never its message: sqlparser embeds the
/// offending token in the text, which for a literal is the plaintext itself.
fn parser_error_kind(error: &ParserError) -> &'static str {
    match error {
        ParserError::TokenizerError(_) => "tokenizer",
        ParserError::ParserError(_) => "parser",
        ParserError::RecursionLimitExceeded => "recursion limit",
    }
}

/// SQLSTATE 42501 (insufficient_privilege): the statement is well-formed, the
/// proxy's policy is what refuses it. Clients treat it as fatal for the
/// statement and do not retry, which is the intent.
const REFUSED_SQLSTATE: &str = "42501";

/// How much of a refusal message goes on the wire. The message embeds SQL
/// identifiers, which are as long as the client cares to make them.
const MAX_ERROR_MESSAGE: usize = 512;

/// A PostgreSQL ErrorResponse ('E') frame. Recoverable at the statement
/// level: the session stays open and the client can carry on.
///
/// Shared with the read path ([`crate::rows`]), which refuses a result set it
/// cannot safely relay with the same frame and the same SQLSTATE: both are the
/// proxy's policy declining one statement, and a client that knows what 42501
/// means from a refused write should not have to learn a second code for a
/// refused read.
pub(crate) fn error_response(message: &str) -> Vec<u8> {
    let mut end = MAX_ERROR_MESSAGE.min(message.len());
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let truncated = &message[..end];
    let mut body = Vec::with_capacity(truncated.len() + 32);
    for (field, value) in
        [(b'S', "ERROR"), (b'V', "ERROR"), (b'C', REFUSED_SQLSTATE), (b'M', truncated)]
    {
        body.push(field);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    frame(b'E', &body)
}

/// Wraps a message body in its `type | length` header.
fn frame(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let length = i32::try_from(pgwire::FRAME_HEADER_LEN - 1 + body.len()).unwrap_or(i32::MAX);
    let mut out = Vec::with_capacity(pgwire::FRAME_HEADER_LEN + body.len());
    out.push(msg_type);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rows::tests::transform;
    use dbsec_core::blind_index;

    fn column(name: &str, transform: Arc<dyn FieldTransform>, searchable: bool) -> ProtectedColumn {
        ProtectedColumn {
            schema: "public".into(),
            table: "users".into(),
            column: name.into(),
            transform: Some(transform),
            searchable,
            readable: true,
            mask: None,
        }
    }

    fn catalog(searchable: bool) -> Arc<WriteCatalog> {
        Arc::new(WriteCatalog::new(
            &[column("email", transform(searchable), searchable)],
            OnUnprotected::Warn,
        ))
    }

    fn strict_catalog(searchable: bool) -> Arc<WriteCatalog> {
        Arc::new(WriteCatalog::new(
            &[column("email", transform(searchable), searchable)],
            OnUnprotected::Reject,
        ))
    }

    /// A rewriter with extended-protocol state of its own; tests that also
    /// drive the read path build the [`SessionPortals`] themselves and share
    /// it (see `rows::tests::session`).
    fn rewriter(catalog: Arc<WriteCatalog>) -> QueryRewriter {
        QueryRewriter::new(catalog, SessionPortals::new(), Arc::new(AtomicU8::new(b'I')), true)
    }

    fn query_frame(sql: &str) -> Vec<u8> {
        let mut body = sql.as_bytes().to_vec();
        body.push(0);
        body
    }

    /// The SQL a Query frame was rewritten into, or `None` when it was
    /// relayed untouched.
    fn rewritten_query(rewriter: &mut QueryRewriter, sql: &str) -> Option<String> {
        match rewriter.on_frame(b'Q', &query_frame(sql)).unwrap() {
            FrameAction::Relay => None,
            FrameAction::Replace(body) => {
                Some(String::from_utf8(body[..body.len() - 1].to_vec()).unwrap())
            }
            FrameAction::Reply(_) | FrameAction::Substitute(_) => panic!("refused: {sql}"),
        }
    }

    /// The ErrorResponse text of a refused frame.
    fn refusal(action: &FrameAction) -> String {
        let FrameAction::Reply(bytes) = action else { panic!("expected a refusal") };
        assert_eq!(bytes[0], b'E', "first frame is an ErrorResponse");
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// Extracts the sealed hex literal out of a rewritten statement and
    /// opens it.
    fn open_hex_literal(sql: &str, searchable: bool) -> Vec<u8> {
        let start = sql.find("'\\x").expect("hex literal") + 3;
        let end = sql[start..].find('\'').unwrap() + start;
        let stored = hex::decode(&sql[start..end]).unwrap();
        transform(searchable).open(&stored).unwrap().expect("opens")
    }

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
        let start = sql.find("'\\x").unwrap() + 3;
        let end = sql[start..].find('\'').unwrap() + start;
        let stored = hex::decode(&sql[start..end]).unwrap();
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

    #[test]
    fn cast_wrapped_searchable_equality_is_rewritten() {
        use crate::rows::tests::INDEX_KEY;

        let mut rewriter = rewriter(catalog(true));
        let hex = hex::encode("alice@example.com");
        let sql = rewritten_query(
            &mut rewriter,
            &format!("SELECT id FROM users WHERE email = '\\x{hex}'::bytea"),
        )
        .expect("rewritten");

        let expected = blind_index::compute(&INDEX_KEY, b"alice@example.com");
        assert!(sql.contains("SUBSTRING(email FROM 1 FOR 32)"), "{sql}");
        assert!(sql.contains(&format!("'\\x{}'", hex::encode(expected))), "{sql}");
    }

    #[test]
    fn unrelated_sql_passes_through() {
        let mut rewriter = rewriter(catalog(false));
        for sql in [
            "SELECT * FROM users",
            "INSERT INTO other (email) VALUES ('x')",
            "UPDATE other SET email = 'x'",
            "this is not SQL at all",
        ] {
            assert!(rewritten_query(&mut rewriter, sql).is_none(), "{sql}");
        }
    }

    #[test]
    fn extended_protocol_seals_bound_params() {
        let mut rewriter = rewriter(catalog(false));

        let parse = pgwire::encode_parse(
            b"stmt1",
            b"INSERT INTO users (id, email) VALUES ($1, $2)",
            &0i16.to_be_bytes(),
        );
        assert!(matches!(rewriter.on_frame(b'P', &parse).unwrap(), FrameAction::Relay));

        // Text-format params: the protected one becomes \x hex.
        let bind = pgwire::encode_bind(
            b"",
            b"stmt1",
            &[],
            &[
                Some(Cow::Borrowed(b"1".as_slice())),
                Some(Cow::Borrowed(b"carol@example.com".as_slice())),
            ],
            &0i16.to_be_bytes(),
        )
        .unwrap();
        let FrameAction::Replace(rewritten) = rewriter.on_frame(b'B', &bind).unwrap() else {
            panic!("bind not rewritten")
        };
        let bound = pgwire::parse_bind(&rewritten).unwrap();
        assert_eq!(bound.params[0], Some(b"1".as_slice()));
        let sealed_hex = bound.params[1].unwrap();
        let stored = hex::decode(sealed_hex.strip_prefix(b"\\x").unwrap()).unwrap();
        assert_eq!(transform(false).open(&stored).unwrap().unwrap(), b"carol@example.com");

        // Binary-format params stay raw bytes.
        let bind = pgwire::encode_bind(
            b"",
            b"stmt1",
            &[1],
            &[
                Some(Cow::Borrowed(b"1".as_slice())),
                Some(Cow::Borrowed(b"dave@example.com".as_slice())),
            ],
            &0i16.to_be_bytes(),
        )
        .unwrap();
        let FrameAction::Replace(rewritten) = rewriter.on_frame(b'B', &bind).unwrap() else {
            panic!("bind not rewritten")
        };
        let bound = pgwire::parse_bind(&rewritten).unwrap();
        assert_eq!(
            transform(false).open(bound.params[1].unwrap()).unwrap().unwrap(),
            b"dave@example.com"
        );

        // Closing the statement forgets it.
        let mut close = vec![b'S'];
        close.extend_from_slice(b"stmt1\0");
        rewriter.on_frame(b'C', &close).unwrap();
        assert!(matches!(rewriter.on_frame(b'B', &bind).unwrap(), FrameAction::Relay));
    }

    #[test]
    fn parse_with_inline_literal_is_rewritten() {
        let mut rewriter = rewriter(catalog(false));
        let parse = pgwire::encode_parse(
            b"",
            b"INSERT INTO users (email) VALUES ('eve@example.com')",
            &0i16.to_be_bytes(),
        );
        let FrameAction::Replace(rewritten) = rewriter.on_frame(b'P', &parse).unwrap() else {
            panic!("parse not rewritten")
        };
        let reparsed = pgwire::parse_parse(&rewritten).unwrap();
        let sql = std::str::from_utf8(reparsed.query).unwrap();
        assert!(!sql.contains("eve@example.com"));
        assert_eq!(open_hex_literal(sql, false), b"eve@example.com");
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
        assert_eq!(fpe.open(pseudonym.as_bytes()).unwrap().unwrap(), b"555-867-5309");
        // Token literal is the 64-char hex HMAC.
        let token_literal = sql.split('\'').nth(3).expect("second literal");
        assert_eq!(token_literal.len(), 64);
        assert_eq!(token_literal.as_bytes(), token.seal(b"abc").unwrap().as_slice());

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
        assert_eq!(fpe.open(sealed).unwrap().unwrap(), b"555-867-5309");
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

    #[test]
    fn searchable_equality_rewrites_to_index_prefix_match() {
        use crate::rows::tests::INDEX_KEY;

        let mut rewriter = rewriter(catalog(true));
        let sql = rewritten_query(
            &mut rewriter,
            "SELECT id FROM users WHERE email = 'alice@example.com'",
        )
        .expect("rewritten");

        let expected = blind_index::compute(&INDEX_KEY, b"alice@example.com");
        assert!(!sql.contains("alice@example.com"), "{sql}");
        assert!(sql.contains("SUBSTRING(email FROM 1 FOR 32)"), "prefix match missing: {sql}");
        assert!(sql.contains(&format!("'\\x{}'", hex::encode(expected))), "{sql}");

        // Aliased and AND-nested references rewrite too; DELETE works.
        let sql = rewritten_query(
            &mut rewriter,
            "DELETE FROM users u WHERE u.id > 4 AND (u.email = 'bob@x.io' OR u.email = 'c@y.io')",
        )
        .expect("rewritten");
        assert!(!sql.contains("bob@x.io") && !sql.contains("c@y.io"), "{sql}");
        assert_eq!(sql.matches("SUBSTRING(u.email FROM 1 FOR 32)").count(), 2, "{sql}");
    }

    #[test]
    fn searchable_equality_placeholder_binds_the_index() {
        use crate::rows::tests::INDEX_KEY;

        let mut rewriter = rewriter(catalog(true));
        let parse = pgwire::encode_parse(
            b"find",
            b"SELECT id FROM users WHERE email = $1",
            &0i16.to_be_bytes(),
        );
        let FrameAction::Replace(rewritten) = rewriter.on_frame(b'P', &parse).unwrap() else {
            panic!("parse not rewritten")
        };
        let reparsed = pgwire::parse_parse(&rewritten).unwrap();
        let sql = std::str::from_utf8(reparsed.query).unwrap();
        assert!(sql.contains("SUBSTRING(email FROM 1 FOR 32) = $1"), "{sql}");

        let bind = pgwire::encode_bind(
            b"",
            b"find",
            &[],
            &[Some(Cow::Borrowed(b"alice@example.com".as_slice()))],
            &0i16.to_be_bytes(),
        )
        .unwrap();
        let FrameAction::Replace(rewritten) = rewriter.on_frame(b'B', &bind).unwrap() else {
            panic!("bind not rewritten")
        };
        let bound = pgwire::parse_bind(&rewritten).unwrap();
        let expected = blind_index::compute(&INDEX_KEY, b"alice@example.com");
        assert_eq!(bound.params[0].unwrap(), format!("\\x{}", hex::encode(expected)).as_bytes());
    }

    #[test]
    fn non_searchable_equality_is_left_alone() {
        let mut rewriter = rewriter(catalog(false));
        for sql in [
            "SELECT id FROM users WHERE email = 'alice@example.com'",
            "SELECT id FROM other WHERE email = 'x'",
            "SELECT id FROM users WHERE id = 4",
        ] {
            assert!(rewritten_query(&mut rewriter, sql).is_none(), "{sql}");
        }
    }

    /// One placeholder cannot be sealed *and* blind-indexed: a Bind carries
    /// one value per placeholder. Before, both actions were applied in
    /// sequence and the index was computed over the ciphertext, so the WHERE
    /// matched nothing and the UPDATE silently affected no rows.
    #[test]
    fn a_placeholder_in_two_protected_roles_is_refused_rather_than_transformed_twice() {
        let mut extended = rewriter(catalog(true));
        let parse = pgwire::encode_parse(
            b"u",
            b"UPDATE users SET email = $1 WHERE email = $1",
            &0i16.to_be_bytes(),
        );
        assert!(matches!(
            extended.on_frame(b'P', &parse),
            Err(Error::ConflictingParameter { placeholder: 1 })
        ));
        // The same shape in the simple protocol has two independent literals,
        // so both roles are served from the plaintext and it still works.
        let mut simple = rewriter(catalog(true));
        let sql = "UPDATE users SET email = 'alice@example.com' WHERE email = 'alice@example.com'";
        let sql = rewritten_query(&mut simple, sql).expect("rewritten");
        assert!(!sql.contains("alice@example.com"), "{sql}");
        assert!(sql.contains("SUBSTRING(email FROM 1 FOR 32)"), "{sql}");
        assert_eq!(open_hex_literal(&sql, true), b"alice@example.com");
        let index = blind_index::compute(&crate::rows::tests::INDEX_KEY, b"alice@example.com");
        assert!(sql.contains(&format!("'\\x{}'", hex::encode(index))), "{sql}");
    }

    /// The same action recorded twice for one placeholder — a multi-row INSERT
    /// repeating `$1` — is one transform. Applying it twice sealed an already
    /// sealed value, which no read path can undo.
    #[test]
    fn a_placeholder_reused_for_one_column_is_sealed_once_not_twice() {
        let mut extended = rewriter(catalog(false));
        let parse = pgwire::encode_parse(
            b"i",
            b"INSERT INTO users (email) VALUES ($1), ($1)",
            &0i16.to_be_bytes(),
        );
        assert!(matches!(extended.on_frame(b'P', &parse).unwrap(), FrameAction::Relay));
        let bind = pgwire::encode_bind(
            b"",
            b"i",
            &[],
            &[Some(Cow::Borrowed(b"alice@example.com".as_slice()))],
            &0i16.to_be_bytes(),
        )
        .unwrap();
        let FrameAction::Replace(rewritten) = extended.on_frame(b'B', &bind).unwrap() else {
            panic!("bind not rewritten")
        };
        let bound = pgwire::parse_bind(&rewritten).unwrap();
        let stored = hex::decode(bound.params[0].unwrap().strip_prefix(b"\\x").unwrap()).unwrap();
        // A double seal would open to the inner ciphertext, not the plaintext.
        assert_eq!(transform(false).open(&stored).unwrap().unwrap(), b"alice@example.com");

        // The simple protocol seals each literal from the plaintext already.
        let mut simple = rewriter(catalog(false));
        let sql = rewritten_query(
            &mut simple,
            "INSERT INTO users (email) VALUES ('bob@x.io'), ('bob@x.io')",
        )
        .expect("rewritten");
        for literal in sql.split("'\\x").skip(1) {
            let stored = hex::decode(&literal[..literal.find('\'').unwrap()]).unwrap();
            assert_eq!(transform(false).open(&stored).unwrap().unwrap(), b"bob@x.io");
        }
    }

    /// `$0` names no bindable parameter. It used to underflow: a panic in
    /// debug builds (a remote panic on a pre-authentication path) and a
    /// rewrite against `usize::MAX` in release ones.
    #[test]
    fn a_zero_placeholder_resolves_to_nothing_and_leaves_the_statement_alone() {
        assert_eq!(placeholder_index("$0"), None);
        assert_eq!(placeholder_index("$1"), Some(0));
        assert_eq!(placeholder_index("$"), None);
        assert_eq!(placeholder_index("$x"), None);
        assert_eq!(placeholder_index("$99999999999999999999999999"), None);

        let mut rewriter = rewriter(catalog(true));
        for sql in [
            "SELECT id FROM users WHERE email = $0",
            "INSERT INTO users (email) VALUES ($0)",
            "UPDATE users SET email = $0 WHERE id = 1",
        ] {
            assert!(rewritten_query(&mut rewriter, sql).is_none(), "{sql}");
            let parse = pgwire::encode_parse(b"", sql.as_bytes(), &0i16.to_be_bytes());
            assert!(
                matches!(rewriter.on_frame(b'P', &parse).unwrap(), FrameAction::Relay),
                "{sql}"
            );
        }
    }

    /// The statement map is keyed by a client-chosen name off the wire, so a
    /// client that never closes what it parses must hit a ceiling (SEC-33).
    #[test]
    fn parse_messages_are_refused_once_the_statement_cap_is_reached() {
        use crate::portal::{MAX_NAME_LEN, MAX_PREPARED_STATEMENTS};

        let mut rewriter = rewriter(catalog(false));
        for i in 0..MAX_PREPARED_STATEMENTS {
            let parse =
                pgwire::encode_parse(format!("s{i}").as_bytes(), b"SELECT 1", &0i16.to_be_bytes());
            rewriter.on_frame(b'P', &parse).expect("within the cap");
        }
        let parse = pgwire::encode_parse(b"one too many", b"SELECT 1", &0i16.to_be_bytes());
        assert!(matches!(rewriter.on_frame(b'P', &parse), Err(Error::SessionLimit { .. })));

        // Closing a statement makes room again.
        let mut close = vec![b'S'];
        close.extend_from_slice(b"s0\0");
        rewriter.on_frame(b'C', &close).unwrap();
        rewriter.on_frame(b'P', &parse).expect("a closed statement freed a slot");

        // The key itself is bounded: a Parse body may be up to 1 GiB.
        let long = vec![b'x'; MAX_NAME_LEN + 1];
        let parse = pgwire::encode_parse(&long, b"SELECT 1", &0i16.to_be_bytes());
        assert!(matches!(
            rewriter.on_frame(b'P', &parse),
            Err(Error::NameTooLong { max: MAX_NAME_LEN, .. })
        ));
    }

    #[test]
    fn malformed_describe_and_close_targets_fail_the_session() {
        let mut rewriter = rewriter(catalog(false));
        for body in [b"X".as_slice(), b"", b"Sunterminated"] {
            assert!(rewriter.on_frame(b'D', body).is_err(), "{body:?}");
            assert!(rewriter.on_frame(b'C', body).is_err(), "{body:?}");
        }
        assert!(rewriter.on_frame(b'E', b"unterminated").is_err());
    }

    #[test]
    fn null_and_unsupported_expressions_pass_through() {
        let mut rewriter = rewriter(catalog(false));
        assert!(rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES (NULL)").is_none());
        assert!(rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES (lower('X'))")
            .is_none());
    }

    // --- fail-closed mode ------------------------------------------------

    /// Each passthrough site is a warning under the default and an
    /// ErrorResponse under `on_unprotected = "reject"`.
    #[test]
    fn every_unprotected_site_passes_through_or_is_refused() {
        let sites: [(&str, &str); 8] = [
            ("INSERT INTO users VALUES (1, 'a@b.io')", "column list"),
            ("INSERT INTO users (email) SELECT email FROM other", "INSERT ... SELECT"),
            ("COPY users (email) FROM STDIN", "COPY"),
            ("INSERT INTO users (email) VALUES (lower('a@b.io'))", "unsupported value"),
            (
                "INSERT INTO users (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET email = lower('x')",
                "conflict action",
            ),
            (
                "MERGE INTO users u USING staging s ON u.id = s.id \
                 WHEN MATCHED THEN UPDATE SET email = s.email",
                "MERGE",
            ),
            ("PREPARE ins AS INSERT INTO users (email) VALUES ('a@b.io')", "PREPARE"),
            ("this is not SQL at all", "unparseable"),
        ];

        let mut permissive = rewriter(catalog(false));
        for (sql, what) in sites {
            let action = permissive.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(
                matches!(action, FrameAction::Relay),
                "{what}: expected a passthrough, got a refusal"
            );
        }

        for (sql, what) in sites {
            let mut strict = rewriter(strict_catalog(false));
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            let message = refusal(&action);
            assert!(message.contains("dbsec refused this statement"), "{what}: {message}");
            let FrameAction::Reply(bytes) = &action else { unreachable!() };
            assert_eq!(bytes[bytes.len() - 6], b'Z', "{what}: ReadyForQuery follows the error");
        }
    }

    /// A non-UTF-8 Query body never reaches the parser; it is still a site.
    #[test]
    fn non_utf8_query_is_refused_in_strict_mode() {
        let mut strict = rewriter(strict_catalog(false));
        let action = strict.on_frame(b'Q', &[0xff, 0xfe, 0]).unwrap();
        assert!(refusal(&action).contains("not valid UTF-8"));

        let mut permissive = rewriter(catalog(false));
        assert!(matches!(permissive.on_frame(b'Q', &[0xff, 0xfe, 0]).unwrap(), FrameAction::Relay));
    }

    /// On the wire a `COPY ... FROM STDIN` has no terminator and no payload —
    /// the rows arrive later as `CopyData` frames — but sqlparser wants one or
    /// the other. Without the retry in [`parse_sql`] the statement reads as
    /// unparseable SQL and both the warning and the refusal name the wrong
    /// problem.
    #[test]
    fn copy_is_recognised_in_both_directions_without_a_terminator() {
        let mut strict = rewriter(strict_catalog(false));
        for (sql, expected) in [
            ("COPY users (email) FROM STDIN", "COPY into protected table users"),
            ("COPY users TO STDOUT", "COPY from protected table users"),
        ] {
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(refusal(&action).contains(expected), "{sql}: {}", refusal(&action));
        }

        // Genuinely unparseable SQL is still reported as such.
        let action = strict.on_frame(b'Q', &query_frame("this is not SQL at all")).unwrap();
        assert!(refusal(&action).contains("could not be parsed"), "{}", refusal(&action));
    }

    /// A refusal inside a transaction reports the aborted state, so the
    /// client rolls back rather than committing around the hole.
    #[test]
    fn refusal_reports_the_backend_transaction_state() {
        let status = Arc::new(AtomicU8::new(b'T'));
        let mut strict =
            QueryRewriter::new(strict_catalog(false), SessionPortals::new(), status.clone(), true);
        let action = strict.on_frame(b'Q', &query_frame("COPY users FROM STDIN")).unwrap();
        let FrameAction::Reply(bytes) = action else { panic!("expected a refusal") };
        assert_eq!(bytes[bytes.len() - 1], b'E', "aborted transaction status");

        status.store(b'I', Ordering::Relaxed);
        let action = strict.on_frame(b'Q', &query_frame("COPY users FROM STDIN")).unwrap();
        let FrameAction::Reply(bytes) = action else { panic!("expected a refusal") };
        assert_eq!(bytes[bytes.len() - 1], b'I', "idle status");
    }

    /// Refusing a Parse puts the proxy in the backend's own error state: the
    /// rest of the batch is discarded and Sync is answered with
    /// ReadyForQuery.
    #[test]
    fn refused_parse_discards_the_batch_until_sync() {
        let mut strict = rewriter(strict_catalog(false));
        let parse = pgwire::encode_parse(b"s", b"COPY users FROM STDIN", &0i16.to_be_bytes());
        let action = strict.on_frame(b'P', &parse).unwrap();
        assert!(refusal(&action).contains("COPY"));

        // Bind and Execute are swallowed: the backend never saw the Parse.
        assert_eq!(strict.on_frame(b'B', b"").unwrap(), FrameAction::Reply(Vec::new()));
        assert_eq!(strict.on_frame(b'E', b"").unwrap(), FrameAction::Reply(Vec::new()));
        let FrameAction::Reply(sync) = strict.on_frame(b'S', b"").unwrap() else {
            panic!("Sync must be answered")
        };
        assert_eq!(sync[0], b'Z');
        // ... and the session carries on.
        assert!(matches!(
            strict.on_frame(b'Q', &query_frame("SELECT 1")).unwrap(),
            FrameAction::Relay
        ));
    }

    // --- upsert and MERGE ------------------------------------------------

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
        assert_eq!(sql.matches("'\\x").count(), 2, "both values sealed: {sql}");

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
            assert_eq!(transform(false).open(&stored).unwrap().unwrap(), expected);
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

    // --- search_path -----------------------------------------------------

    /// The mis-protection direction: a bare name in a session that moved
    /// `search_path` must not be sealed for `public.users`, because the value
    /// would land in a table the read path never resolves.
    #[test]
    fn moved_search_path_stops_sealing_unqualified_names() {
        let mut rewriter = rewriter(catalog(false));
        assert!(rewritten_query(&mut rewriter, "SET search_path TO myschema").is_none());
        assert!(
            rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('a@b.io')").is_none(),
            "an unqualified name must not be sealed once search_path moved"
        );
        // Qualifying the name puts it back beyond doubt.
        let sql =
            rewritten_query(&mut rewriter, "INSERT INTO public.users (email) VALUES ('a@b.io')")
                .expect("rewritten");
        assert!(!sql.contains("a@b.io"), "{sql}");
    }

    #[test]
    fn default_search_path_stays_trusted() {
        let mut rewriter = rewriter(catalog(false));
        for sql in ["SET search_path TO public", "SET search_path = \"$user\", public"] {
            assert!(rewritten_query(&mut rewriter, sql).is_none(), "{sql}");
        }
        let sql = rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('a@b.io')")
            .expect("rewritten");
        assert!(!sql.contains("a@b.io"), "{sql}");
    }

    #[test]
    fn strict_mode_refuses_a_search_path_change() {
        let mut strict = rewriter(strict_catalog(false));
        let action = strict.on_frame(b'Q', &query_frame("SET search_path TO tenant7")).unwrap();
        assert!(refusal(&action).contains("search_path"));
    }

    /// A session that started with a `search_path` in its startup packet is
    /// untrusted from the first statement.
    #[test]
    fn untrusted_session_never_seals_unqualified_names() {
        let mut rewriter = QueryRewriter::new(
            catalog(false),
            SessionPortals::new(),
            Arc::new(AtomicU8::new(b'I')),
            false,
        );
        assert!(
            rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('a@b.io')").is_none()
        );
    }

    // --- SQL text fidelity -----------------------------------------------

    /// Only the statement that changed is re-rendered; the rest of the batch
    /// reaches the server byte-for-byte as the client wrote it.
    #[test]
    fn untouched_statements_keep_their_original_text() {
        let mut rewriter = rewriter(catalog(false));
        let original = "/* keep me */ SELECT 1 -- and me\n; INSERT INTO users (email) \
                        VALUES ('a@b.io') ;  SELECT   'x'  ,  $tag$ raw ; body $tag$ ;";
        let sql = rewritten_query(&mut rewriter, original).expect("rewritten");
        assert!(sql.starts_with("/* keep me */ SELECT 1 -- and me\n; "), "{sql}");
        assert!(sql.ends_with(";  SELECT   'x'  ,  $tag$ raw ; body $tag$ ;"), "{sql}");
        assert!(!sql.contains("a@b.io"), "{sql}");
        assert_eq!(open_hex_literal(&sql, false), b"a@b.io");
    }

    #[test]
    fn statement_ranges_respect_quoting_and_comments() {
        let sql = "SELECT ';', \";\", $q$;$q$, E'\\'; ' /* ; */ -- ;\n; SELECT 2";
        let ranges = statement_ranges(sql).expect("splits");
        assert_eq!(
            ranges.len(),
            2,
            "{:?}",
            ranges.iter().map(|r| &sql[r.clone()]).collect::<Vec<_>>()
        );
        assert_eq!(&sql[ranges[1].clone()], "SELECT 2");

        // Unterminated constructs are not guessed at.
        assert!(statement_ranges("SELECT 'oops").is_none());
        assert!(statement_ranges("SELECT $q$oops").is_none());
        assert!(statement_ranges("SELECT 1 /* oops").is_none());
    }

    /// A rendered statement that does not re-parse to the same AST never
    /// reaches the server.
    #[test]
    fn rendered_statements_are_validated() {
        let statement =
            &Parser::parse_sql(&PostgreSqlDialect {}, "SELECT 1 FROM t").unwrap().pop().unwrap();
        assert_eq!(render_validated(statement).unwrap(), "SELECT 1 FROM t");
    }

    // --- searchable predicates -------------------------------------------

    #[test]
    fn in_list_and_any_array_rewrite_to_index_matches() {
        use crate::rows::tests::INDEX_KEY;

        let mut rewriter = rewriter(catalog(true));
        let expected = blind_index::compute(&INDEX_KEY, b"a@b.io");
        for sql in [
            "SELECT id FROM users WHERE email IN ('a@b.io', 'c@d.io')",
            "SELECT id FROM users WHERE email = ANY(ARRAY['a@b.io', 'c@d.io'])",
        ] {
            let rewritten = rewritten_query(&mut rewriter, sql).expect("rewritten");
            assert!(!rewritten.contains("a@b.io"), "{rewritten}");
            assert!(rewritten.contains("SUBSTRING(email FROM 1 FOR 32)"), "{rewritten}");
            assert!(rewritten.contains(&hex::encode(expected)), "{rewritten}");
        }

        // Bound placeholders in the list are indexed at Bind time.
        let parse = pgwire::encode_parse(
            b"in",
            b"SELECT id FROM users WHERE email IN ($1, $2)",
            &0i16.to_be_bytes(),
        );
        let FrameAction::Replace(rewritten) = rewriter.on_frame(b'P', &parse).unwrap() else {
            panic!("parse not rewritten")
        };
        let reparsed = pgwire::parse_parse(&rewritten).unwrap();
        assert!(std::str::from_utf8(reparsed.query)
            .unwrap()
            .contains("SUBSTRING(email FROM 1 FOR 32) IN ($1, $2)"));
        let bind = pgwire::encode_bind(
            b"",
            b"in",
            &[],
            &[Some(Cow::Borrowed(b"a@b.io".as_slice())), Some(Cow::Borrowed(b"c@d.io".as_slice()))],
            &0i16.to_be_bytes(),
        )
        .unwrap();
        let FrameAction::Replace(rewritten) = rewriter.on_frame(b'B', &bind).unwrap() else {
            panic!("bind not rewritten")
        };
        let bound = pgwire::parse_bind(&rewritten).unwrap();
        assert_eq!(bound.params[0].unwrap(), format!("\\x{}", hex::encode(expected)).as_bytes());
    }

    /// A binary-format array parameter: `ndim | flags | element oid`, one
    /// `length | lower bound` pair, then `length | bytes` per element.
    fn binary_array(element_oid: i32, elements: &[Option<&[u8]>]) -> Vec<u8> {
        let mut out = 1i32.to_be_bytes().to_vec();
        out.extend_from_slice(&i32::from(elements.iter().any(Option::is_none)).to_be_bytes());
        out.extend_from_slice(&element_oid.to_be_bytes());
        out.extend_from_slice(&(elements.len() as i32).to_be_bytes());
        out.extend_from_slice(&1i32.to_be_bytes());
        for element in elements {
            match element {
                None => out.extend_from_slice(&(-1i32).to_be_bytes()),
                Some(bytes) => {
                    out.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                    out.extend_from_slice(bytes);
                }
            }
        }
        out
    }

    /// Parses a statement and returns the rewritten SQL text.
    fn rewritten_parse(
        rewriter: &mut QueryRewriter,
        statement: &[u8],
        sql: &str,
    ) -> Option<String> {
        let parse = pgwire::encode_parse(statement, sql.as_bytes(), &0i16.to_be_bytes());
        match rewriter.on_frame(b'P', &parse).unwrap() {
            FrameAction::Relay => None,
            FrameAction::Replace(body) => {
                Some(String::from_utf8(pgwire::parse_parse(&body).unwrap().query.to_vec()).unwrap())
            }
            FrameAction::Reply(_) | FrameAction::Substitute(_) => panic!("refused: {sql}"),
        }
    }

    fn bind_frame(statement: &[u8], formats: &[i16], params: &[Option<&[u8]>]) -> Vec<u8> {
        let params: Vec<_> = params.iter().map(|p| p.map(Cow::Borrowed)).collect();
        pgwire::encode_bind(b"", statement, formats, &params, &0i16.to_be_bytes()).unwrap()
    }

    /// `= ANY($1)` is the shape sqlx and asyncpg give a multi-value lookup:
    /// one bound array, not a list of placeholders. The SQL is the same
    /// index-prefix match `ARRAY[...]` produces; the array itself is decoded,
    /// indexed and re-encoded as `bytea[]` at Bind time.
    #[test]
    fn a_bound_any_array_is_indexed_element_by_element_at_bind_time() {
        use crate::rows::tests::INDEX_KEY;

        let indexed = |value: &[u8]| blind_index::compute(&INDEX_KEY, value);
        let mut rewriter = rewriter(catalog(true));
        let sql =
            rewritten_parse(&mut rewriter, b"any", "SELECT id FROM users WHERE email = ANY($1)")
                .expect("rewritten");
        assert!(sql.contains("SUBSTRING(email FROM 1 FOR 32) = ANY($1)"), "{sql}");

        // Binary format: bytea[] in, bytea[] out, NULL elements preserved.
        let array = binary_array(17, &[Some(b"a@b.io"), None, Some(b"c@d.io")]);
        let FrameAction::Replace(rewritten) =
            rewriter.on_frame(b'B', &bind_frame(b"any", &[1], &[Some(&array)])).unwrap()
        else {
            panic!("bind not rewritten")
        };
        let bound = pgwire::parse_bind(&rewritten).unwrap();
        assert_eq!(
            bound.params[0].unwrap(),
            binary_array(17, &[Some(&indexed(b"a@b.io")), None, Some(&indexed(b"c@d.io"))]),
        );

        // Text format: an array literal of `\x` hex, with the backslash
        // escaped the way a quoted array element needs it.
        let FrameAction::Replace(rewritten) = rewriter
            .on_frame(b'B', &bind_frame(b"any", &[0], &[Some(b"{a@b.io,NULL,\"c@d.io\"}")]))
            .unwrap()
        else {
            panic!("bind not rewritten")
        };
        let bound = pgwire::parse_bind(&rewritten).unwrap();
        assert_eq!(
            bound.params[0].unwrap(),
            format!(
                "{{\"\\\\x{}\",NULL,\"\\\\x{}\"}}",
                hex::encode(indexed(b"a@b.io")),
                hex::encode(indexed(b"c@d.io"))
            )
            .as_bytes(),
        );
    }

    /// An array the codec cannot index faithfully must not go on the wire
    /// half-indexed: that is a *valid* query returning the wrong rows. It
    /// falls back to the same signal the SQL rewrite raises, one message
    /// later.
    #[test]
    fn an_undecodable_any_array_falls_back_to_the_predicate_signal() {
        // An int4 element type: not a value this proxy ever sealed.
        let ints = binary_array(23, &[Some(&1i32.to_be_bytes())]);
        // Truncated, and a nested array literal.
        let truncated = binary_array(17, &[Some(b"a@b.io")]);
        let truncated = truncated[..truncated.len() - 2].to_vec();
        for (format, param) in [
            (1i16, ints),
            (1, truncated),
            (0, b"{{a@b.io},{c@d.io}}".to_vec()),
            (0, b"[1:2]={a@b.io,c@d.io}".to_vec()),
        ] {
            let mut permissive = rewriter(catalog(true));
            rewritten_parse(&mut permissive, b"any", "SELECT id FROM users WHERE email = ANY($1)")
                .expect("rewritten");
            let bind = bind_frame(b"any", &[format], &[Some(&param)]);
            let relayed = match permissive.on_frame(b'B', &bind).unwrap() {
                FrameAction::Relay => param.clone(),
                FrameAction::Replace(body) => {
                    pgwire::parse_bind(&body).unwrap().params[0].unwrap().to_vec()
                }
                FrameAction::Reply(_) | FrameAction::Substitute(_) => {
                    panic!("warn must not refuse: {param:?}")
                }
            };
            assert_eq!(relayed, param, "warn relays the array untouched");

            let mut strict = rewriter(strict_catalog(true));
            rewritten_parse(&mut strict, b"any", "SELECT id FROM users WHERE email = ANY($1)")
                .expect("rewritten");
            let action = strict.on_frame(b'B', &bind).unwrap();
            assert!(refusal(&action).contains("searchable column email"), "{param:?}");
            // The refusal owns the batch until Sync, exactly like a refused
            // Parse: the backend never saw the Bind.
            assert_eq!(
                strict.on_frame(b'E', b"\0\0\0\0\0").unwrap(),
                FrameAction::Reply(Vec::new())
            );
            let FrameAction::Reply(ready) = strict.on_frame(b'S', b"").unwrap() else {
                panic!("Sync answers with ReadyForQuery")
            };
            assert_eq!(ready[0], b'Z');
        }
    }

    /// The other parameters of a Bind are still transformed when one array
    /// cannot be indexed — a sealed parameter relayed as plaintext because
    /// some *other* parameter was undecodable would write the plaintext this
    /// proxy exists to keep out of the database.
    #[test]
    fn a_fallback_array_does_not_drop_the_other_parameters_of_its_bind() {
        let mut rewriter = rewriter(catalog(true));
        let sql = rewritten_parse(
            &mut rewriter,
            b"mixed",
            "UPDATE users SET email = $1 WHERE email = ANY($2)",
        );
        assert!(sql.is_some());
        let ints = binary_array(23, &[Some(&1i32.to_be_bytes())]);
        let bind = bind_frame(b"mixed", &[1], &[Some(b"new@b.io"), Some(&ints)]);
        let FrameAction::Replace(rewritten) = rewriter.on_frame(b'B', &bind).unwrap() else {
            panic!("the sealed parameter must still be sealed")
        };
        let bound = pgwire::parse_bind(&rewritten).unwrap();
        assert_ne!(bound.params[0].unwrap(), b"new@b.io");
        assert_eq!(bound.params[1].unwrap(), ints, "the array is relayed as it came");
    }

    #[test]
    fn the_array_codec_reads_what_postgres_writes_and_refuses_the_rest() {
        let elements = |array: BoundArray| array.elements;
        // Quoted elements escape `"` and `\`; unquoted NULL is a NULL element.
        let text = decode_text_array(br#"{ "a,b" , plain , NULL , "q\"\\x" }"#, WireForm::Text)
            .expect("a flat array");
        assert_eq!(
            elements(text),
            [Some(b"a,b".to_vec()), Some(b"plain".to_vec()), None, Some(b"q\"\\x".to_vec()),]
        );
        // A BYTEA-form column reads `\x` as hex input, the same as a literal.
        assert_eq!(
            elements(decode_text_array(b"{\\x616263}", WireForm::Bytea).unwrap()),
            [Some(b"abc".to_vec())]
        );
        assert!(decode_text_array(b"{}", WireForm::Text).unwrap().elements.is_empty());
        for refused in [&b"{a,b"[..], b"a,b}", b"{{a},{b}}", b"[1:1]={a}", b"{a} trailing"] {
            assert!(decode_text_array(refused, WireForm::Text).is_none(), "{refused:?}");
        }

        // Binary: only element types whose bytes are the plaintext.
        let array = decode_binary_array(&binary_array(25, &[Some(b"a"), None])).expect("a text[]");
        assert_eq!(array.lower_bound, 1);
        assert_eq!(elements(array), [Some(b"a".to_vec()), None]);
        assert!(decode_binary_array(&binary_array(23, &[Some(b"\0\0\0\x01")])).is_none());
        assert!(decode_binary_array(b"").is_none());
        // Trailing bytes mean it was not the array it claimed to be.
        let mut trailing = binary_array(17, &[Some(b"a")]);
        trailing.push(0);
        assert!(decode_binary_array(&trailing).is_none());
        // An element length past the end of the message.
        let mut lying = binary_array(17, &[Some(b"a")]);
        let last = lying.len() - 5;
        lying[last..last + 4].copy_from_slice(&99i32.to_be_bytes());
        assert!(decode_binary_array(&lying).is_none());
    }

    #[test]
    fn join_cte_and_set_operations_are_traversed() {
        let mut rewriter = rewriter(catalog(true));
        for sql in [
            "SELECT u.id FROM users u JOIN orders o ON o.id = u.id AND u.email = 'a@b.io'",
            "WITH hits AS (SELECT id FROM users WHERE email = 'a@b.io') SELECT * FROM hits",
            "SELECT id FROM users WHERE email = 'a@b.io' UNION SELECT id FROM orders",
            "SELECT id FROM (SELECT id, email FROM users WHERE email = 'a@b.io') AS s",
            "SELECT count(*) FROM users GROUP BY email HAVING email = 'a@b.io'",
        ] {
            let rewritten = rewritten_query(&mut rewriter, sql).unwrap_or_else(|| panic!("{sql}"));
            assert!(!rewritten.contains("a@b.io"), "{rewritten}");
            assert!(rewritten.contains("FROM 1 FOR 32"), "{rewritten}");
        }
    }

    /// A shape the rewriter cannot express is a refusal site, not a silent
    /// "no rows".
    #[test]
    fn unsupported_predicates_over_searchable_columns_are_signalled() {
        for sql in [
            "SELECT id FROM users WHERE email LIKE 'a%'",
            "SELECT id FROM users WHERE email > 'a@b.io'",
            "SELECT id FROM users WHERE email IN (SELECT email FROM other)",
            "SELECT id FROM users WHERE email = ANY(SELECT email FROM other)",
            "SELECT id FROM users WHERE email IN ('a@b.io', lower('c@d.io'))",
            "DELETE FROM users WHERE email = lower('a@b.io')",
        ] {
            let mut permissive = rewriter(catalog(true));
            assert!(rewritten_query(&mut permissive, sql).is_none(), "{sql}");

            let mut strict = rewriter(strict_catalog(true));
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(refusal(&action).contains("searchable column email"), "{sql}");
        }
    }

    /// Predicates over columns the proxy does not protect stay silent.
    #[test]
    fn unsupported_predicates_over_other_columns_stay_quiet() {
        let mut strict = rewriter(strict_catalog(true));
        for sql in [
            "SELECT id FROM users WHERE id > 4",
            "SELECT id FROM users WHERE name LIKE 'a%'",
            "SELECT id FROM other WHERE email LIKE 'a%'",
        ] {
            assert!(
                matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
                "{sql}"
            );
        }
    }

    // --- logging ---------------------------------------------------------

    /// The plaintext bound to a protected column must not reach the log, so
    /// the warning carries the column and the expression's shape instead.
    #[test]
    fn unsupported_value_warning_names_the_shape_not_the_value() {
        let site = Unprotected::UnsupportedValue { column: "email", shape: "function call" };
        let message = site.message();
        assert!(message.contains("email") && message.contains("function call"), "{message}");

        let parsed = Parser::parse_sql(&PostgreSqlDialect {}, "SELECT lower('a@b.io')").unwrap();
        let Statement::Query(query) = &parsed[0] else { panic!("a query") };
        let SetExpr::Select(select) = query.body.as_ref() else { panic!("a select") };
        let sqlparser::ast::SelectItem::UnnamedExpr(expr) = &select.projection[0] else {
            panic!("an expression")
        };
        assert_eq!(expr_shape(expr), "function call");
        assert!(!expr_shape(expr).contains("a@b.io"));
    }

    /// The parser's own message embeds the token it choked on — which for a
    /// literal is the plaintext — so only the variant is logged.
    #[test]
    fn parser_errors_are_reduced_to_their_kind() {
        let error = parse_sql("UPDATE users SET email 'a@b.io'").expect_err("does not parse");
        assert!(format!("{error}").contains("a@b.io"), "precondition: the message leaks");
        let site = Unprotected::Unparseable(&error);
        assert!(!site.message().contains("a@b.io"), "{}", site.message());
        assert_eq!(parser_error_kind(&error), "parser");
    }

    /// Everything the write path emits while it is the active subscriber, one
    /// string per event. Asserting on the code's *shape* is not enough here:
    /// the claim is about what reaches the log, so the test reads the log.
    #[derive(Clone, Default)]
    struct CapturedEvents(Arc<std::sync::Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CapturedEvents {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Fields<'a>(&'a mut String);
            impl tracing::field::Visit for Fields<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    use std::fmt::Write as _;
                    let _ = write!(self.0, " {}={value:?}", field.name());
                }
            }
            let mut line = String::new();
            event.record(&mut Fields(&mut line));
            self.0.lock().expect("captured events").push(line);
        }
    }

    /// Every passthrough site, driven with a distinct plaintext, and then the
    /// whole log grepped for those plaintexts. Each of these values is bound
    /// to a protected column or embedded in SQL the parser choked on, so any
    /// of them appearing in an event is the disclosure this module's logging
    /// rules exist to prevent.
    #[test]
    fn no_event_from_the_write_path_carries_a_plaintext_value() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let captured = CapturedEvents::default();
        let subscriber = tracing_subscriber::registry().with(captured.clone());
        tracing::subscriber::with_default(subscriber, || {
            let mut rewriter = rewriter(catalog(true));
            for sql in [
                "INSERT INTO users (email) VALUES (lower('alice@secret.test'))",
                "UPDATE users SET email = concat('bob', '@secret.test')",
                "INSERT INTO users VALUES (1, 'carol@secret.test')",
                "INSERT INTO users (email) SELECT email FROM other",
                "COPY users (email) FROM STDIN",
                "MERGE INTO users u USING staging s ON u.id = s.id \
                 WHEN MATCHED THEN UPDATE SET email = s.email",
                "PREPARE ins AS INSERT INTO users (email) VALUES ('dave@secret.test')",
                "SELECT id FROM users WHERE email LIKE 'erin@secret.test%'",
                "SELECT id FROM users WHERE email IN ('fred@secret.test', lower('x'))",
                "UPDATE users SET email 'gina@secret.test'",
                "SET search_path TO tenant7",
                "INSERT INTO users (email) VALUES ('hank@secret.test')",
            ] {
                // Errors are the point of some of these; only the log matters.
                drop(rewriter.on_frame(b'Q', &query_frame(sql)));
            }
        });

        let events = captured.0.lock().unwrap().join("\n");
        assert!(events.contains("passing through unencrypted"), "the sites did emit: {events}");
        for plaintext in ["alice", "bob", "carol", "dave", "erin", "fred", "gina", "hank", "secret"]
        {
            assert!(!events.contains(plaintext), "{plaintext} reached the log:\n{events}");
        }
    }

    #[test]
    fn error_response_is_a_well_formed_frame() {
        let bytes = error_response("nope");
        assert_eq!(bytes[0], b'E');
        let length = i32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
        assert_eq!(length, bytes.len() - 1);
        assert_eq!(*bytes.last().unwrap(), 0, "field list is terminated");
        let body = String::from_utf8_lossy(&bytes[5..]);
        assert!(body.contains("ERROR") && body.contains(REFUSED_SQLSTATE) && body.contains("nope"));

        // A message longer than the cap is truncated, not dropped.
        let long = error_response(&"x".repeat(4096));
        assert!(long.len() < 4096);
    }
}
