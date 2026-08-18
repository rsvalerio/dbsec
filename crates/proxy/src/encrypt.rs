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
//! changed `search_path`, a session that turned
//! `standard_conforming_strings` off and every backslash-carrying literal
//! after it, an unqualified column matching a protected column in more than
//! one relation in scope, and a predicate over a searchable column the
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
//! that mentions a protected column — `LIKE`, ordering comparisons,
//! `IN (SELECT ...)`, `= ANY(SELECT ...)` — is an [`Unprotected`] site rather
//! than a silent no-op, because comparing a client's plaintext against the
//! stored form matches no row and reads as an empty result rather than an
//! error. So is an array parameter the codec cannot decode faithfully: the
//! signal moves to Bind time, but it is the same signal.
//!
//! The test is *protected*, not *searchable*. What makes an unrewritten
//! predicate wrong is that the stored form is not the plaintext, which holds
//! for `encrypt` without `searchable`, for `fpe` and for `token` exactly as it
//! does for a searchable column — those are merely the subset the rewriter can
//! also *fix*. So `WHERE email = '…'` on a non-searchable column is
//! [`Unprotected::UnindexedPredicate`], reported separately from
//! [`Unprotected::Predicate`] because the remedy differs: one is a query to
//! rewrite, the other a column to reconfigure. Mask-only columns are outside
//! all of this — [`WriteCatalog::new`] skips columns with no transform, so
//! they store the plaintext and their predicates are correct as written.
//!
//! `IS NULL` and `IS NOT NULL` are the one exception, and they are exempt for
//! the same reason the rest are not: nullness is the one property sealing
//! preserves exactly, so those two match the rows the client meant and there
//! is nothing to signal. Reporting them would refuse working SQL under
//! `reject` and dilute the warning stream under `warn` — a signal that fires
//! on correct queries stops being read. See [`protected_operand`].
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
    Assignment, AssignmentTarget, Expr, FunctionArg, FunctionArgExpr, GroupByExpr, Ident, Insert,
    JoinConstraint, JoinOperator, ObjectName, OnConflict, OnConflictAction, OnInsert, Query,
    Select, SelectItem, SetExpr, Statement, TableFactor, TableWithJoins, Value,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::{Parser, ParserError};
use sqlparser::tokenizer::{Token, Tokenizer};

use crate::columns::ProtectedColumn;
use crate::config::{fold_identifier, OnUnprotected};
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
    /// The tables the *read* path has something to do to, which is a superset
    /// of `tables`: a mask-only column has no transform, so it is not in the
    /// write catalog at all, but the mask applied on the way out is the only
    /// thing protecting it. See [`Self::protects_reads`].
    read_tables: HashSet<(String, String)>,
    /// The `bare_names` of `read_tables`.
    read_bare_names: HashSet<String>,
    on_unprotected: OnUnprotected,
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
    fn table(&self, name: &ObjectName) -> Option<&Columns> {
        self.tables.get(&resolved_name(name)?)
    }

    /// Whether an unqualified name matches a protected table in *some* schema.
    fn may_be_protected(&self, name: &ObjectName) -> bool {
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
    fn protects_reads(&self, name: &ObjectName) -> bool {
        resolved_name(name).is_some_and(|key| self.read_tables.contains(&key))
    }

    /// [`Self::may_be_protected`] for the read direction.
    fn may_protect_reads(&self, name: &ObjectName) -> bool {
        name.0.last().is_some_and(|ident| self.read_bare_names.contains(&normalize(ident)))
    }
}

/// A SQL table name as the catalog keys it: `(schema, table)`, with an
/// unqualified name resolved against `public`.
fn resolved_name(name: &ObjectName) -> Option<(String, String)> {
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
fn normalize(ident: &Ident) -> String {
    fold_identifier(&ident.value, ident.quote_style.is_some()).into_owned()
}

/// Why a rewrite stopped: the session cannot continue, or this one statement
/// is refused and the client is told why.
enum Rejection {
    /// A crypto or wire failure: fail the session rather than relay anything.
    /// Boxed because this variant travels in the `Err` of most of the
    /// rewrite's return types, and [`Error`] is large enough that inlining it
    /// would make every one of them wide (`clippy::result_large_err`).
    Fatal(Box<Error>),
    /// This one statement is refused and the session carries on: either
    /// `on_unprotected = "reject"` met a site it will not let through, or the
    /// statement is unrewritable under any setting ([`record_param`]).
    Refused(String),
}

impl From<Error> for Rejection {
    fn from(error: Error) -> Self {
        Self::Fatal(Box::new(error))
    }
}

/// Records what Bind must do to one placeholder, turning the single refusal
/// [`ParamTransforms::record`] can raise into a *statement-level* one.
///
/// `INSERT INTO users (email, backup_email) VALUES ($1, $1)` with the two
/// columns under different transforms — or `UPDATE users SET email = $1 WHERE
/// email = $1`, which needs the sealed value in the SET and the blind index in
/// the WHERE — is valid client SQL, not a protocol violation. The Bind carries
/// one value per placeholder, so only one of the two answers fits on the wire
/// and the statement cannot be honoured. Refusing it is the whole remedy:
/// nothing has gone upstream at this point, so the same
/// [`SqlOutcome::Refuse`] path every other unrewritable statement takes
/// applies unchanged.
///
/// It used to travel as [`Rejection::Fatal`], which tore the session down over
/// well-formed SQL and told the client nothing but a closed socket — and under
/// a connection pool the retry killed the next connection too.
///
/// Unlike an [`Unprotected`] site this does not consult `on_unprotected`:
/// there is no "warn and relay" answer available. Letting it through would
/// seal a value and then blind-index the ciphertext, or seal an already-sealed
/// value — silently, and irreversibly in the second case (CL-3), which is the
/// outcome [`ParamTransforms`] exists to prevent.
fn record_param(
    params: &mut ParamTransforms,
    index: usize,
    action: ParamAction,
) -> Result<(), Rejection> {
    match params.record(index, action) {
        Ok(()) => Ok(()),
        Err(Error::ConflictingParameter { placeholder }) => Err(Rejection::Refused(format!(
            "dbsec refused this statement: placeholder ${placeholder} feeds two protected \
             positions that need different values, and a Bind carries one value per \
             placeholder; give each position its own placeholder"
        ))),
        Err(other) => Err(Rejection::Fatal(Box::new(other))),
    }
}

/// What one SQL text turned into.
enum SqlOutcome {
    /// Relay it (`rewritten` is `None`) or send the replacement text.
    Rewrite(RewriteOutcome),
    /// Refuse it with this message.
    Refuse(String),
}

/// What sealing an `INSERT`'s `VALUES` list did.
#[derive(Default)]
struct SealedValues {
    /// Whether a value was rewritten, so the statement needs re-rendering.
    changed: bool,
    /// The protected columns the rows carried, normalized — the columns whose
    /// values went through [`QueryRewriter::seal_expr`], which is what makes
    /// `EXCLUDED.<col>` safe to re-store in the conflict action. A value
    /// `seal_expr` could not seal is not silently included: it raised its own
    /// [`Unprotected::UnsupportedValue`] there, so under `reject` the
    /// statement never reaches the conflict action at all, and under `warn`
    /// the plaintext it re-stores is the plaintext already being inserted.
    columns: HashSet<String>,
}

/// What an assignment list may write into: the target table's protected
/// columns, and what the rest of the same statement already sealed.
struct AssignmentScope<'a> {
    columns: &'a Columns,
    sealed: SealedValues,
}

impl AssignmentScope<'_> {
    /// A plain `UPDATE`: no `EXCLUDED` relation exists, so no value in this
    /// statement is one the proxy sealed a clause earlier.
    fn of(columns: &Columns) -> AssignmentScope<'_> {
        AssignmentScope { columns, sealed: SealedValues::default() }
    }

    /// Whether `value` is `EXCLUDED.<column>` naming a column this `INSERT`'s
    /// `VALUES` list already sealed.
    ///
    /// `INSERT ... ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email` is
    /// the canonical PostgreSQL upsert, and `EXCLUDED.email` is exactly the
    /// value this proxy sealed a few clauses earlier — storing it stores the
    /// sealed form, which is what the column is supposed to hold. There is no
    /// plaintext here to seal, so treating it as
    /// [`Unprotected::UnsupportedValue`] refused correct SQL outright under
    /// `reject`: an availability false positive of the kind that keeps
    /// operators on the permissive default instead of enabling fail-closed.
    ///
    /// The whitelist is deliberately narrow, because a reference that is *not*
    /// provably already sealed would write plaintext with no signal at all:
    ///
    /// - the qualifier must be the `EXCLUDED` pseudo-relation, not another
    ///   table in the statement;
    /// - the column must be the same column being assigned — a different one
    ///   was sealed under a different column's transform, so its stored form
    ///   is not a value this column can be read back through;
    /// - and it must be one the `VALUES` list actually carried. `EXCLUDED.c`
    ///   for a column the INSERT did not list is that column's default, which
    ///   nothing sealed.
    fn re_stores_a_sealed_value(&self, value: &Expr, column: &str) -> bool {
        let Expr::CompoundIdentifier(idents) = value else { return false };
        let [qualifier, referenced] = idents.as_slice() else { return false };
        normalize(qualifier) == "excluded"
            && normalize(referenced) == column
            && self.sealed.columns.contains(column)
    }
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
    /// Whether the session turned `standard_conforming_strings` off. With it
    /// off, PostgreSQL reads a backslash in an ordinary `'…'` literal as the
    /// start of an escape and sqlparser does not, so the two no longer agree
    /// on what such a literal contains.
    escape_strings: bool,
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
        Self {
            catalog,
            portals,
            tx_status,
            search_path_trusted,
            escape_strings: false,
            awaiting_sync: false,
        }
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
            // CopyData, CopyDone, CopyFail. In copy-in mode these are the
            // payload, and the backend is ignoring the Sync the client already
            // pipelined. Outside it they are strays PostgreSQL discards
            // without answering — and `copy_data` refuses to move the queue
            // for them, because a client that could pop this batch's marker
            // could desync every response behind it. Relayed either way: the
            // backend's own handling of a stray frame is the authority, and
            // withholding it would only differ from PostgreSQL.
            b'd' | b'c' | b'f' => {
                self.portals.copy_data(msg_type);
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
        // Every column whose array could not be indexed, not just the last one:
        // an operator handed one name out of two fixes that site and hits the
        // other on the next run.
        let mut unindexed: Vec<String> = Vec::new();
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
                            unindexed.push(column.to_string());
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
        if !unindexed.is_empty() {
            let site =
                Unprotected::Predicate { column: unindexed.join(", "), shape: "= ANY bound array" };
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

    /// Whether a literal denotes the same bytes to the server as to the
    /// proxy's parser.
    ///
    /// Only an ordinary `'…'` literal can disagree, and only once the session
    /// has turned `standard_conforming_strings` off: from then on the server
    /// reads a backslash in one as the start of an escape, while sqlparser
    /// keeps reading it as a backslash. `E'…'`, `U&'…'` and dollar quoting all
    /// have backslash rules the setting does not touch, so they always agree.
    ///
    /// Sealing a literal the two read differently would store the plaintext
    /// the proxy guessed rather than the one the client wrote — unrecoverable,
    /// because nothing downstream can tell it apart from a correctly sealed
    /// value. Reporting it instead leaves the data intact and names the reason.
    fn literal_agrees_with_server(&self, expr: &Expr) -> bool {
        if !self.escape_strings {
            return true;
        }
        !matches!(
            unwrap_casts(expr),
            Expr::Value(Value::SingleQuotedString(text)) if text.contains('\\')
        )
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

    /// [`Self::table`] for the read direction: whether reading this table
    /// streams something the read path is supposed to open or mask. See
    /// [`WriteCatalog::protects_reads`] for why the two lookups differ.
    fn reads_protected(&self, name: &ObjectName) -> Result<bool, Rejection> {
        if self.search_path_trusted || name.0.len() > 1 {
            return Ok(self.catalog.protects_reads(name));
        }
        if self.catalog.may_protect_reads(name) {
            self.unprotected(&Unprotected::SearchPath(name))?;
        }
        Ok(false)
    }

    fn rewrite_sql(&mut self, query: &[u8]) -> Result<SqlOutcome, Error> {
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
        let moved = settings_moved(text);
        let parsed = parse_sql(text);
        // The groups line up with the statements only when the tokenizer and
        // the parser saw the same batch. Unparseable text (where nothing is
        // rewritten, so no ordering can change an outcome) and any other
        // disagreement fall back to applying every move up front, which is the
        // conservative reading.
        let aligned = parsed.as_ref().is_ok_and(|statements| statements.len() == moved.len());
        if !aligned {
            match self.note_session_state(&moved.concat()) {
                Ok(()) => {}
                Err(Rejection::Fatal(error)) => return Err(*error),
                Err(Rejection::Refused(message)) => return Ok(SqlOutcome::Refuse(message)),
            }
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
    /// about to be relayed. Once `search_path` stops making `public` the
    /// schema of an unqualified name, the write path stops resolving bare
    /// names at all; `standard_conforming_strings` is reported but changes no
    /// catalog assumption, because what it invalidates is the proxy's reading
    /// of the client's own literals.
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

    fn rewrite_statement(
        &self,
        statement: &mut Statement,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        match statement {
            Statement::Insert(insert) => self.rewrite_insert(insert, params),
            Statement::Update { table, assignments, from, selection, .. } => {
                let mut changed = false;
                if let TableFactor::Table { name, .. } = &table.relation {
                    if let Some(columns) = self.table(name)? {
                        let target = AssignmentScope::of(columns);
                        changed |= self.seal_assignments(assignments, &target, params)?;
                    }
                }
                // `UPDATE ... FROM other` is a join: the predicate resolves
                // names against the joined relation as well as the target, so
                // a searchable column of *that* relation is as much a rewrite
                // site as the target's own. Dropping it with the `..` left the
                // comparison relayed verbatim — no rewrite, and no signal.
                let scope = self.scope(std::iter::once(&*table).chain(from.as_ref()))?;
                // A join constraint in that FROM resolves against the same
                // scope the WHERE does, so it is the same rewrite site — and
                // one only `rewrite_select` used to walk.
                changed |= self.rewrite_join_conditions(
                    std::iter::once(&mut *table).chain(from.as_mut()),
                    &scope,
                    params,
                )?;
                if let Some(selection) = selection {
                    changed |= self.rewrite_predicate(selection, &scope, params)?;
                }
                // `SET x = (SELECT ...)` on an unprotected column still hides a
                // query whose own predicates need rewriting.
                for assignment in assignments.iter_mut() {
                    changed |= self.rewrite_nested_queries(&mut assignment.value, params)?;
                }
                changed |=
                    self.rewrite_derived_tables(std::iter::once(&mut *table).chain(from), params)?;
                Ok(changed)
            }
            Statement::Query(query) => self.rewrite_query(query, params),
            Statement::Delete(delete) => {
                let tables = match &delete.from {
                    sqlparser::ast::FromTable::WithFromKeyword(tables)
                    | sqlparser::ast::FromTable::WithoutKeyword(tables) => tables,
                };
                // `USING` is the DELETE spelling of `UPDATE ... FROM`, and it
                // is a separate field: a predicate over the joined relation
                // resolves against it, so it belongs in the scope too. Left
                // out, `DELETE FROM sessions USING users WHERE users.email =
                // $1` compares plaintext against the stored form and deletes
                // nothing — and its `<>` inversion deletes everything.
                let scope = self.scope(tables.iter().chain(delete.using.iter().flatten()))?;
                let mut changed = false;
                if let Some(selection) = delete.selection.as_mut() {
                    changed |= self.rewrite_predicate(selection, &scope, params)?;
                }
                let tables = match &mut delete.from {
                    sqlparser::ast::FromTable::WithFromKeyword(tables)
                    | sqlparser::ast::FromTable::WithoutKeyword(tables) => tables,
                };
                // Same as the UPDATE arm: a `USING a JOIN b ON …` constraint
                // resolves against this scope and is as much a rewrite site as
                // the WHERE.
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
            Statement::Copy { source, to, .. } => {
                match source {
                    sqlparser::ast::CopySource::Table { table_name, .. } => {
                        // The two directions ask different questions of the
                        // catalog. `COPY … FROM STDIN` is a write, so what
                        // matters is whether a value would have needed sealing
                        // — a plaintext bulk load into a mask-only column is
                        // correct and must not be refused. `COPY … TO` is a
                        // read, and its rows leave as `CopyData` frames the
                        // read path relays verbatim, so a mask-only column
                        // leaves as the plaintext its mask exists to hide.
                        let protected = if *to {
                            self.reads_protected(table_name)?
                        } else {
                            self.table(table_name)?.is_some()
                        };
                        if protected {
                            self.unprotected(&Unprotected::Copy { table: table_name, to: *to })?;
                        }
                    }
                    // `COPY (SELECT ...) TO STDOUT`. PostgreSQL only allows a
                    // query source in the *out* direction, and its rows leave
                    // as `CopyData` frames — which the read path relays
                    // verbatim, because only `DataRow` carries the column
                    // identity decryption needs. So this form streams the
                    // stored value of every protected column it projects, and
                    // it used to do so with no signal at all: the classifier
                    // looked at `CopySource::Table` only, so `reject` refused
                    // `COPY users TO STDOUT` and relayed
                    // `COPY (SELECT email FROM users) TO STDOUT`.
                    //
                    // The query is classified *and* rewritten. Classified
                    // first, so `reject` refuses the leak before anything is
                    // rendered; rewritten second, because under `warn` the
                    // statement is relayed and its predicates are ordinary
                    // predicates — a searchable equality left alone compares
                    // the client's plaintext against the stored
                    // `blind_index || envelope` and matches no row, which is
                    // the failure [`Self::rewrite_nested_queries`] documents
                    // as the unsafe one.
                    //
                    // Only the `TO` direction is rewritten, and that is what
                    // keeps the re-rendering safe: PostgreSQL allows a query
                    // source only on the way out, so a statement that changes
                    // here is never a `COPY ... FROM STDIN` — the one COPY
                    // shape with no wire-valid rendering through sqlparser's
                    // `Display` (see [`parse_sql`], which parses it only by
                    // appending a terminator the wire cannot carry). Anything
                    // not rewritten keeps its original source text verbatim
                    // ([`reassemble`]), and anything that is rewritten is
                    // re-parsed and compared before it is sent
                    // ([`render_validated`]).
                    sqlparser::ast::CopySource::Query(query) => {
                        for table in self.copied_protected_tables(query)? {
                            self.unprotected(&Unprotected::CopyQuery { table })?;
                        }
                        if *to {
                            return self.rewrite_query(query, params);
                        }
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
            }],
        };
        let target = AssignmentScope { columns, sealed };
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

    fn rewrite_insert_values(
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
        let mut sealed = SealedValues::default();
        for row in &mut values.rows {
            for (position, ident, transform) in &protected {
                if let Some(expr) = row.get_mut(*position) {
                    sealed.changed |= self.seal_expr(expr, transform, &ident.value, params)?;
                }
            }
        }
        sealed.columns = protected.iter().map(|(_, ident, _)| normalize(ident)).collect();
        Ok(sealed)
    }

    /// Seals every assignment that targets a protected column. Shared by
    /// `UPDATE` and by `INSERT ... ON CONFLICT DO UPDATE`.
    fn seal_assignments(
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
                    changed |= self.seal_expr(value, &transform, &name, params)?;
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
            if target.re_stores_a_sealed_value(&elements[*position], &normalize(ident)) {
                continue;
            }
            changed |= self.seal_expr(&mut elements[*position], transform, &ident.value, params)?;
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
        if let Some(order_by) = query.order_by.as_mut() {
            for order in &mut order_by.exprs {
                changed |= self.rewrite_nested_queries(&mut order.expr, params)?;
            }
        }
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
        let mut changed = self.rewrite_join_conditions(&mut select.from, &scope, params)?;
        changed |= self.rewrite_derived_tables(&mut select.from, params)?;
        for predicate in [select.selection.as_mut(), select.having.as_mut()].into_iter().flatten() {
            changed |= self.rewrite_predicate(predicate, &scope, params)?;
        }
        // Subqueries sitting in an *expression* rather than in FROM. These
        // carry their own FROM, so they are walked by `rewrite_query` against
        // their own scope; the predicate pass above deliberately stops at the
        // subquery boundary, which is what keeps each query rewritten once.
        // A protected column computed over in the projection loses its table
        // identity on the way back, so the read path cannot act on it. Decided
        // here, where the statement still says which column it was.
        for item in &select.projection {
            if let Some((column, expr)) = computed_protected_column(item, &scope) {
                self.unprotected(&Unprotected::ComputedColumn { column, shape: expr_shape(expr) })?;
            }
        }
        for expr in select_expressions(select) {
            changed |= self.rewrite_nested_queries(expr, params)?;
        }
        Ok(changed)
    }

    /// Rewrites the derived tables of a relation list against their own
    /// scopes.
    ///
    /// A derived table carries its own FROM, so its predicates belong to its
    /// own traversal rather than the enclosing one. Every clause that holds
    /// relations needs this pass, not only `SELECT`: `UPDATE ... FROM (SELECT
    /// ...)` and `DELETE ... USING (SELECT ...)` walked their own `WHERE` but
    /// never descended into the subquery next to it, so a searchable equality
    /// in there was left comparing plaintext against the stored form — no
    /// rewrite, no signal, and no rows.
    fn rewrite_derived_tables<'from>(
        &self,
        from: impl IntoIterator<Item = &'from mut TableWithJoins>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let mut changed = false;
        for table in from {
            for factor in std::iter::once(&mut table.relation)
                .chain(table.joins.iter_mut().map(|join| &mut join.relation))
            {
                match factor {
                    TableFactor::Derived { subquery, .. } => {
                        changed |= self.rewrite_query(subquery, params)?;
                    }
                    // A derived table inside a parenthesised join, e.g.
                    // `FROM (users JOIN (SELECT ... WHERE email = '…') s ON …)`.
                    // See [`Self::scope_of`] for why the nesting hides it.
                    TableFactor::NestedJoin { table_with_joins, .. } => {
                        changed |= self.rewrite_derived_tables(
                            std::iter::once(&mut **table_with_joins),
                            params,
                        )?;
                    }
                    _ => {}
                }
            }
        }
        Ok(changed)
    }

    /// Rewrites the `ON` conditions of a relation list against the enclosing
    /// scope, descending into parenthesised joins.
    ///
    /// A join constraint over a searchable column is as much a rewrite site as
    /// a `WHERE` is, and the constraints of a join written as
    /// `FROM (a JOIN b ON …)` live in the [`TableFactor::NestedJoin`]'s own
    /// [`TableWithJoins`] — never in the top-level `joins` list a flat pass
    /// looks at.
    fn rewrite_join_conditions<'from>(
        &self,
        from: impl IntoIterator<Item = &'from mut TableWithJoins>,
        scope: &TableScope<'_>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let mut changed = false;
        for table in from {
            changed |= self.rewrite_nested_join(&mut table.relation, scope, params)?;
            for join in &mut table.joins {
                changed |= self.rewrite_nested_join(&mut join.relation, scope, params)?;
                if let Some(constraint) = join_condition(&mut join.join_operator) {
                    changed |= self.rewrite_selection(constraint, scope, params)?;
                }
            }
        }
        Ok(changed)
    }

    /// The [`Self::rewrite_join_conditions`] step for one factor: recurse when
    /// it is a parenthesised join, and do nothing otherwise.
    fn rewrite_nested_join(
        &self,
        factor: &mut TableFactor,
        scope: &TableScope<'_>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let TableFactor::NestedJoin { table_with_joins, .. } = factor else { return Ok(false) };
        self.rewrite_join_conditions(std::iter::once(&mut **table_with_joins), scope, params)
    }

    /// A predicate owned by a statement or select: rewritten against its own
    /// scope, then swept for nested queries.
    ///
    /// Both halves are needed at every site that owns a `WHERE`, and keeping
    /// them behind one call is what stops a site being given only one of them
    /// — which is exactly how `DELETE` and `UPDATE` came to walk their
    /// predicates without ever crossing into a subquery.
    fn rewrite_predicate(
        &self,
        expr: &mut Expr,
        scope: &TableScope<'_>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let mut changed = self.rewrite_selection(expr, scope, params)?;
        changed |= self.rewrite_nested_queries(expr, params)?;
        Ok(changed)
    }

    /// Rewrites every query nested inside an expression, and nothing else.
    ///
    /// The counterpart to [`Self::rewrite_selection`], which rewrites
    /// predicates inside one scope and never crosses a subquery boundary.
    /// Splitting the two jobs this way is what makes the traversal safe:
    /// each [`Query`] is reached from exactly one place, so no predicate can
    /// be rewritten twice. Recursion into a nested query stops here because
    /// [`Self::rewrite_query`] walks its insides itself.
    ///
    /// Before this existed, `rewrite_select` descended only into FROM-clause
    /// derived tables, CTE bodies and set-operation branches. A searchable
    /// equality inside a scalar subquery, an `EXISTS`, or a projection item
    /// was left comparing the client's plaintext against the stored
    /// `blind_index || envelope` — matching nothing, and never reaching
    /// [`Self::unprotected`], so `reject` did not flag it either.
    ///
    /// "Matches nothing" is not a safe failure mode. `DELETE FROM t WHERE id
    /// NOT IN (SELECT id FROM users WHERE email = '...')` turns an empty
    /// subquery result into `NOT IN (empty)`, which is true for every row, so
    /// the statement deletes the whole table.
    fn rewrite_nested_queries(
        &self,
        expr: &mut Expr,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let mut changed = false;
        // The children to walk, gathered first: a closure capturing `changed`
        // would borrow it for the whole match.
        let mut children: Vec<&mut Expr> = Vec::new();
        match expr {
            // A query boundary: `rewrite_query` takes it from here, so the
            // walk deliberately does not descend past this point.
            Expr::Subquery(query) | Expr::Exists { subquery: query, .. } => {
                return self.rewrite_query(query, params);
            }
            Expr::InSubquery { expr: operand, subquery, .. } => {
                changed |= self.rewrite_query(subquery, params)?;
                children.push(operand.as_mut());
            }
            Expr::BinaryOp { left, right, .. }
            | Expr::AnyOp { left, right, .. }
            | Expr::AllOp { left, right, .. }
            | Expr::IsDistinctFrom(left, right)
            | Expr::IsNotDistinctFrom(left, right) => {
                children.push(left.as_mut());
                children.push(right.as_mut());
            }
            Expr::UnaryOp { expr: inner, .. }
            | Expr::Nested(inner)
            | Expr::Cast { expr: inner, .. }
            | Expr::IsNull(inner)
            | Expr::IsNotNull(inner)
            | Expr::IsTrue(inner)
            | Expr::IsNotTrue(inner)
            | Expr::IsFalse(inner)
            | Expr::IsNotFalse(inner)
            | Expr::Collate { expr: inner, .. } => children.push(inner.as_mut()),
            Expr::InList { expr: operand, list, .. } => {
                children.push(operand.as_mut());
                children.extend(list.iter_mut());
            }
            Expr::Between { expr: operand, low, high, .. } => {
                children.push(operand.as_mut());
                children.push(low.as_mut());
                children.push(high.as_mut());
            }
            Expr::Like { expr: operand, pattern, .. }
            | Expr::ILike { expr: operand, pattern, .. }
            | Expr::SimilarTo { expr: operand, pattern, .. } => {
                children.push(operand.as_mut());
                children.push(pattern.as_mut());
            }
            Expr::Tuple(items) => children.extend(items.iter_mut()),
            Expr::Case { operand, conditions, results, else_result } => {
                children.extend(operand.iter_mut().map(AsMut::as_mut));
                children.extend(else_result.iter_mut().map(AsMut::as_mut));
                children.extend(conditions.iter_mut());
                children.extend(results.iter_mut());
            }
            Expr::Function(function) => {
                if let sqlparser::ast::FunctionArguments::List(list) = &mut function.args {
                    for argument in &mut list.args {
                        let (FunctionArg::Named { arg, .. }
                        | FunctionArg::ExprNamed { arg, .. }
                        | FunctionArg::Unnamed(arg)) = argument;
                        if let FunctionArgExpr::Expr(inner) = arg {
                            children.push(inner);
                        }
                    }
                }
            }
            // Everything else is a leaf, or a shape that cannot hold a query.
            // A miss here leaves the pre-existing behaviour rather than
            // opening a new hole, and an *outer* predicate over a protected
            // column is still signalled by `rewrite_selection`.
            _ => {}
        }
        for child in children {
            changed |= self.rewrite_nested_queries(child, params)?;
        }
        Ok(changed)
    }

    /// Collects the protected tables visible to a predicate, with their
    /// aliases, so column references can be resolved.
    ///
    /// Takes an iterator rather than a slice because the relations a predicate
    /// sees are not always contiguous: `UPDATE ... FROM` keeps its second
    /// relation in a field of its own, next to the target.
    fn scope<'from>(
        &self,
        from: impl IntoIterator<Item = &'from TableWithJoins>,
    ) -> Result<TableScope<'_>, Rejection> {
        let mut tables = Vec::new();
        for table_with_joins in from {
            self.scope_of(table_with_joins, &mut tables)?;
        }
        Ok(TableScope { tables })
    }

    /// Adds one relation and its joins to a scope, descending into the
    /// parenthesised joins sqlparser keeps as [`TableFactor::NestedJoin`].
    ///
    /// `FROM (users JOIN orders ON orders.id = users.id)` parses as a single
    /// `NestedJoin` holding the whole join rather than as two `Table` factors,
    /// so a walk that stops at the top level finds no table at all: every
    /// protected table inside the parentheses drops out of the scope, and a
    /// predicate over one is neither rewritten into an index match nor raised
    /// as an [`Unprotected`] site — so `reject` relayed it verbatim and the
    /// comparison matched no row. The parentheses only group the join; the
    /// names inside them are in scope for the enclosing query exactly as they
    /// would be without them, which is why the nesting is flattened away here.
    fn scope_of<'a>(
        &'a self,
        table_with_joins: &TableWithJoins,
        tables: &mut Vec<ScopedTable<'a>>,
    ) -> Result<(), Rejection> {
        let factors = std::iter::once(&table_with_joins.relation)
            .chain(table_with_joins.joins.iter().map(|join| &join.relation));
        for factor in factors {
            match factor {
                TableFactor::Table { name, alias, .. } => {
                    let Some(columns) = self.table(name)? else { continue };
                    tables.push(ScopedTable {
                        alias: alias.as_ref().map(|alias| normalize(&alias.name)),
                        name: name.0.iter().map(normalize).collect(),
                        columns,
                    });
                }
                TableFactor::NestedJoin { table_with_joins, .. } => {
                    self.scope_of(table_with_joins, tables)?;
                }
                // A derived table brings its own scope, and a set-returning
                // function, `UNNEST` or `JSON_TABLE` names no base table the
                // catalog could resolve.
                _ => {}
            }
        }
        Ok(())
    }

    /// Every protected table a `COPY (query) TO STDOUT` would read, gathered
    /// from the query's own FROM clauses, its derived tables, its CTE bodies
    /// and both branches of a set operation. Names are reported once each,
    /// however many times the query mentions them.
    ///
    /// The *table* is what is reported, not the column. A COPY query's
    /// projection is arbitrary SQL — `SELECT *`, a function call, a reference
    /// to a CTE that selects the column three levels down — so "does this
    /// stream a protected column" is not answerable from the statement text,
    /// and answering "no" wrongly is the failure that leaks. Naming the table
    /// is also what the table-form `COPY t TO STDOUT` already does, so the two
    /// forms of one statement now behave alike.
    ///
    /// This walk recognises one table shape [`Self::scope`] does not — the
    /// `PIVOT`/`UNPIVOT`/`MATCH_RECOGNIZE` wrappers — because the consequence
    /// of missing one differs. There, a missed table leaves a predicate
    /// unrewritten, which the client sees as an empty result; here it hands
    /// the client a protected column's stored bytes. (The parenthesised join
    /// used to be the second such shape; [`Self::scope_of`] descends into it
    /// now, since the empty result it caused was no safer.)
    fn copied_protected_tables(&self, query: &Query) -> Result<Vec<String>, Rejection> {
        let mut found = Vec::new();
        self.collect_copied_tables(query, &mut found)?;
        Ok(found)
    }

    fn collect_copied_tables(
        &self,
        query: &Query,
        found: &mut Vec<String>,
    ) -> Result<(), Rejection> {
        if let Some(with) = query.with.as_ref() {
            for cte in &with.cte_tables {
                self.collect_copied_tables(&cte.query, found)?;
            }
        }
        self.collect_copied_tables_in(&query.body, found)
    }

    fn collect_copied_tables_in(
        &self,
        body: &SetExpr,
        found: &mut Vec<String>,
    ) -> Result<(), Rejection> {
        match body {
            SetExpr::Select(select) => {
                for table in &select.from {
                    let factors = std::iter::once(&table.relation)
                        .chain(table.joins.iter().map(|join| &join.relation));
                    for factor in factors {
                        self.collect_copied_tables_from(factor, found)?;
                    }
                }
            }
            SetExpr::Query(query) => self.collect_copied_tables(query, found)?,
            SetExpr::SetOperation { left, right, .. } => {
                self.collect_copied_tables_in(left, found)?;
                self.collect_copied_tables_in(right, found)?;
            }
            // `TABLE t`, the shorthand for `SELECT * FROM t`, which the parser
            // keeps as a pair of bare strings rather than an `ObjectName`.
            //
            // sqlparser 0.53 cannot actually reach this arm from a COPY
            // source: `parse_as_table` reads three tokens unconditionally and
            // so overruns the closing paren, leaving `COPY (TABLE t) TO
            // STDOUT` unparseable — which is a site of its own, so the shape
            // is refused under `reject` today by a different name. The arm is
            // here so a later parser fix cannot quietly open a hole.
            SetExpr::Table(table) => {
                let Some(name) = table.table_name.as_ref() else { return Ok(()) };
                let parts = table.schema_name.iter().chain(std::iter::once(name));
                let name = ObjectName(parts.map(|part| Ident::new(part.as_str())).collect());
                self.record_copied_table(&name, found)?;
            }
            // A data-modifying CTE writes; it is the write path's own sites
            // that cover it, and its rows are not what COPY streams.
            SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Values(_) => {}
        }
        Ok(())
    }

    fn collect_copied_tables_from(
        &self,
        factor: &TableFactor,
        found: &mut Vec<String>,
    ) -> Result<(), Rejection> {
        match factor {
            TableFactor::Table { name, .. } => self.record_copied_table(name, found),
            TableFactor::Derived { subquery, .. } => self.collect_copied_tables(subquery, found),
            TableFactor::NestedJoin { table_with_joins, .. } => {
                let factors = std::iter::once(&table_with_joins.relation)
                    .chain(table_with_joins.joins.iter().map(|join| &join.relation));
                for factor in factors {
                    self.collect_copied_tables_from(factor, found)?;
                }
                Ok(())
            }
            TableFactor::Pivot { table, .. }
            | TableFactor::Unpivot { table, .. }
            | TableFactor::MatchRecognize { table, .. } => {
                self.collect_copied_tables_from(table, found)
            }
            // Set-returning functions, `UNNEST`, `JSON_TABLE`: none of them
            // names a table the catalog could resolve.
            _ => Ok(()),
        }
    }

    fn record_copied_table(
        &self,
        name: &ObjectName,
        found: &mut Vec<String>,
    ) -> Result<(), Rejection> {
        // The read-direction lookup: a query source only exists in the `TO`
        // direction, and a mask-only table read this way streams the plaintext
        // its mask exists to hide. See [`WriteCatalog::protects_reads`].
        if !self.reads_protected(name)? {
            return Ok(());
        }
        let name = name.to_string();
        if !found.contains(&name) {
            found.push(name);
        }
        Ok(())
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
                    record_param(
                        params,
                        index,
                        ParamAction::SearchIndexArray { transform, column },
                    )?;
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
        let Some(transform) = column_ref(scope, column).cloned() else {
            if let Some(column) = ambiguous_column(column, scope) {
                self.unprotected(&Unprotected::AmbiguousColumn { column, shape: "IN list" })?;
                return Ok(false);
            }
            // Row-wise `(a, b) IN ((..), (..))`: no single transform covers a
            // row constructor, so it cannot be rewritten — but it still has to
            // be reported rather than relayed to match nothing.
            if let Some((column, searchable)) = protected_column(column, scope) {
                self.unprotected(&if searchable {
                    Unprotected::Predicate { column, shape: "row-wise IN list" }
                } else {
                    Unprotected::UnindexedPredicate { column, shape: "row-wise IN list" }
                })?;
            }
            return Ok(false);
        };
        if !transform.supports_search() {
            // Same as `rewrite_equality`: no index to compare against, so
            // every element would be tested against the stored form.
            let column = column_name(column).unwrap_or_default();
            self.unprotected(&Unprotected::UnindexedPredicate { column, shape: "IN list" })?;
            return Ok(false);
        }
        if !list.iter().all(|value| self.literal_agrees_with_server(value)) {
            let column = column_name(column).unwrap_or_default();
            self.unprotected(&Unprotected::AmbiguousLiteral { column: &column })?;
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
            // The column is protected but carries no equality index, so this
            // comparison would run against the stored form and match nothing.
            // Relaying it silently is the failure `Unprotected` exists to
            // prevent: "no rows" reads as "no such user".
            let column = column_name(column).unwrap_or_default();
            self.unprotected(&Unprotected::UnindexedPredicate {
                column,
                shape: expr_shape(value),
            })?;
            return Ok(false);
        }
        if !self.literal_agrees_with_server(value) {
            let column = column_name(column).unwrap_or_default();
            self.unprotected(&Unprotected::AmbiguousLiteral { column: &column })?;
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
    /// signal when it actually mentions a protected column — otherwise it is
    /// ordinary SQL the proxy has no business commenting on.
    fn unsupported_predicate(
        &self,
        expr: &Expr,
        scope: &TableScope<'_>,
    ) -> Result<bool, Rejection> {
        let shape = expr_shape(expr);
        // Checked first: an ambiguous name resolves to no transform, so the
        // protected-operand test below cannot see it, and it is precisely the
        // case that must not be left as a plaintext comparison.
        if let Some(column) = ambiguous_operand(expr, scope) {
            self.unprotected(&Unprotected::AmbiguousColumn { column, shape })?;
            return Ok(false);
        }
        let Some((column, searchable)) = protected_operand(expr, scope) else { return Ok(false) };
        self.unprotected(&if searchable {
            Unprotected::Predicate { column, shape }
        } else {
            Unprotected::UnindexedPredicate { column, shape }
        })?;
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
                    record_param(params, index, ParamAction::Seal(transform.clone()))?;
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
        let sealed = transform.seal(&plaintext).map_err(Error::Wire)?;
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

/// A session setting the rewrite's assumptions depend on, moved off the value
/// those assumptions need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettingMoved {
    /// `search_path` no longer resolves an unqualified name to `public`.
    SearchPath,
    /// `standard_conforming_strings` is no longer `on`, so PostgreSQL reads a
    /// backslash in an ordinary string literal as the start of an escape and
    /// the proxy's parser does not.
    EscapeStrings,
}

/// The settings each statement of one SQL text moves, read from its **token
/// stream** and grouped per top-level statement, in order.
///
/// Not from the parsed statements, because they cannot see three of the four
/// forms that move a setting: sqlparser 0.53 rejects `SET SCHEMA 'tenant7'`
/// outright (it arrives as [`Unprotected::Unparseable`], which under `warn`
/// relays it), and `set_config('search_path', 'tenant7', false)` is an
/// ordinary function call that may sit anywhere in any statement. Tokens see
/// every form, and — unlike searching the raw text — cannot mistake the same
/// characters inside a string literal or a quoted identifier for the keyword
/// or the function name.
///
/// Grouping rather than flattening is what keeps a multi-statement batch
/// honest: a move belongs to the statements after it, not to the ones in front
/// of it, so `INSERT …; SET search_path …` still seals the insert.
///
/// `RESET` is deliberately absent: it restores whatever the role or the server
/// makes the default, which is the same value the connect-time assumption
/// already trusts, so treating it as a move would contradict that assumption
/// rather than tighten it.
fn settings_moved(text: &str) -> Vec<Vec<SettingMoved>> {
    let Ok(all) = Tokenizer::new(&PostgreSqlDialect {}, text).tokenize() else {
        // Text that does not tokenize does not parse either, so it is already
        // reported as unparseable; there is nothing to add here.
        return Vec::new();
    };
    // Whitespace and comments are both `Whitespace` tokens, and neither
    // separates a keyword from what it applies to.
    let tokens: Vec<&Token> =
        all.iter().filter(|token| !matches!(token, Token::Whitespace(_))).collect();

    // An empty run is the trailing semicolon, or one written twice; sqlparser
    // does not count either as a statement, so neither does this.
    tokens
        .split(|token| matches!(token, Token::SemiColon))
        .filter(|statement| !statement.is_empty())
        .map(statement_settings_moved)
        .collect()
}

/// The settings one statement moves. `tokens` are that statement's, with the
/// whitespace and the terminating semicolon already gone.
fn statement_settings_moved(tokens: &[&Token]) -> Vec<SettingMoved> {
    let mut moved = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let rest = &tokens[index + 1..];
        let found = match keyword(token).as_deref() {
            // `SET` also opens the assignment list of an `UPDATE`, where the
            // name that follows is a column: only a statement-initial `SET` is
            // the session command.
            Some("set") if index == 0 => set_statement(rest),
            Some("set_config") => set_config_call(rest),
            _ => None,
        };
        if let Some(setting) = found {
            if !moved.contains(&setting) {
                moved.push(setting);
            }
        }
    }
    moved
}

/// The lowercased text of an unquoted word. A quoted one is an identifier the
/// client chose, never a keyword or a function name the server resolves.
fn keyword(token: &Token) -> Option<String> {
    match token {
        Token::Word(word) if word.quote_style.is_none() => Some(word.value.to_ascii_lowercase()),
        _ => None,
    }
}

/// `SET [SESSION | LOCAL] <name> {= | TO} <value…>`, and PostgreSQL's
/// `SET SCHEMA <value>` shorthand for a one-element `search_path`. `tokens`
/// starts just after the `SET`.
fn set_statement(tokens: &[&Token]) -> Option<SettingMoved> {
    let mut rest = tokens;
    if matches!(keyword(rest.first()?).as_deref(), Some("session" | "local")) {
        rest = rest.get(1..)?;
    }
    let name = keyword(rest.first()?)?;
    rest = rest.get(1..)?;
    if name == "schema" {
        return moved_by("search_path", setting_values(rest));
    }
    if !matches!(rest.first()?, Token::Eq) && keyword(rest.first()?).as_deref() != Some("to") {
        return None;
    }
    moved_by(&name, setting_values(rest.get(1..)?))
}

/// `set_config('<setting>', '<value>', <is_local>)` — the function spelling of
/// `SET`, which reaches the server inside an ordinary query. `tokens` starts
/// just after the function name.
fn set_config_call(tokens: &[&Token]) -> Option<SettingMoved> {
    if !matches!(tokens.first()?, Token::LParen) {
        return None;
    }
    // A setting name that is not a literal could be `search_path`, and the
    // assumption that unqualified names resolve to `public` cannot survive a
    // change the proxy is unable to read.
    let Some(Token::SingleQuotedString(setting)) = tokens.get(1) else {
        return Some(SettingMoved::SearchPath);
    };
    if !matches!(tokens.get(2)?, Token::Comma) {
        return Some(SettingMoved::SearchPath);
    }
    moved_by(&setting.to_ascii_lowercase(), setting_values(tokens.get(3..4)?))
}

/// Whether assigning `values` to `name` moves a tracked setting. `None` values
/// mean the assignment could not be read, which counts as a move: a setting
/// the proxy cannot evaluate is one it cannot keep assuming.
fn moved_by(name: &str, values: Option<Vec<String>>) -> Option<SettingMoved> {
    match name {
        "search_path" => {
            (!is_default_search_path(values.as_deref())).then_some(SettingMoved::SearchPath)
        }
        "standard_conforming_strings" => {
            (!is_on(values.as_deref())).then_some(SettingMoved::EscapeStrings)
        }
        _ => None,
    }
}

/// The elements a setting is being assigned, stopping at the end of the
/// statement or of the enclosing call. A list may be written as separate
/// tokens (`SET search_path TO tenant7, public`) or as one string
/// (`set_config('search_path', 'tenant7, public', false)`), so both are split
/// down to the same shape. `None` means a token this cannot evaluate.
fn setting_values(tokens: &[&Token]) -> Option<Vec<String>> {
    let mut values = Vec::new();
    for token in tokens {
        match token {
            Token::SemiColon | Token::RParen => break,
            Token::Comma => {}
            Token::Word(word) if word.quote_style.is_some() => values.push(word.value.clone()),
            Token::Word(word) => values.push(word.value.to_ascii_lowercase()),
            Token::SingleQuotedString(text) => {
                values.extend(text.split(',').map(|part| part.trim().trim_matches('"').to_owned()))
            }
            Token::Number(number, _) => values.push(number.clone()),
            _ => return None,
        }
    }
    Some(values)
}

/// Whether a `search_path` value still leaves `public` as the schema an
/// unqualified name resolves to. `"$user", public` is PostgreSQL's own default
/// and stays trusted; anything else in front of `public` does not, because a
/// bare name may resolve there instead.
fn is_default_search_path(values: Option<&[String]>) -> bool {
    let Some(values) = values else { return false };
    values.iter().all(|name| name == "public" || name == "$user")
        && values.iter().any(|name| name == "public")
}

/// Whether a boolean setting is being turned on, in any of the spellings
/// PostgreSQL accepts. `DEFAULT` is not one of them: the default is whatever
/// the server was configured with, which the proxy cannot read.
fn is_on(values: Option<&[String]>) -> bool {
    matches!(values, Some([value]) if matches!(
        value.as_str(),
        "on" | "true" | "t" | "yes" | "y" | "1"
    ))
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

/// What a scope made of a column reference.
///
/// Ambiguity is a case of its own rather than a second spelling of "not
/// found": an unqualified name matching a protected column in two relations
/// cannot be rewritten — guessing which table's blind index to compare against
/// is exactly the wrong-rows outcome the rewrite exists to prevent — but it
/// still *is* a predicate over a protected column, so it has to reach
/// [`QueryRewriter::unprotected`]. Collapsing it into "no protected column
/// here" left the comparison relayed with nothing but a log line, refused by
/// nothing, matching no row.
enum ColumnResolution<'a> {
    /// Exactly one protected column in scope carries this name.
    One(&'a Arc<dyn FieldTransform>),
    /// More than one does, and no rewrite can choose between them.
    Ambiguous,
    /// No protected column in scope carries this name.
    Unknown,
}

impl TableScope<'_> {
    /// Resolves a (possibly qualified) column reference to its transform.
    fn resolve(&self, idents: &[Ident]) -> ColumnResolution<'_> {
        let Some((column, qualifiers)) = idents.split_last() else {
            return ColumnResolution::Unknown;
        };
        let column = normalize(column);
        let mut matches = self
            .tables
            .iter()
            .filter(|table| table.matches(qualifiers))
            .filter_map(|table| table.columns.get(&column));
        let Some(transform) = matches.next() else { return ColumnResolution::Unknown };
        if matches.next().is_some() {
            ColumnResolution::Ambiguous
        } else {
            ColumnResolution::One(transform)
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

/// How a scope resolves an expression that may be a column reference.
fn resolve_column<'a>(scope: &'a TableScope<'_>, expr: &Expr) -> ColumnResolution<'a> {
    match expr {
        Expr::Identifier(ident) => scope.resolve(std::slice::from_ref(ident)),
        Expr::CompoundIdentifier(idents) => scope.resolve(idents),
        _ => ColumnResolution::Unknown,
    }
}

/// The transform of a column reference that resolves to exactly one protected
/// column. An ambiguous one deliberately does not: see [`ColumnResolution`].
fn column_ref<'a>(scope: &'a TableScope<'_>, expr: &Expr) -> Option<&'a Arc<dyn FieldTransform>> {
    match resolve_column(scope, expr) {
        ColumnResolution::One(transform) => Some(transform),
        ColumnResolution::Ambiguous | ColumnResolution::Unknown => None,
    }
}

/// The direct sub-expressions of `expr`, for read-only walks.
///
/// The mutable twin of this lives in
/// [`QueryRewriter::rewrite_nested_queries`]; it stops at query boundaries
/// because it hands them to `rewrite_query`, whereas this one descends into
/// them, since a protected column referenced inside a subquery is still
/// projected out of it.
fn expr_operands(expr: &Expr) -> Vec<&Expr> {
    match expr {
        Expr::BinaryOp { left, right, .. }
        | Expr::AnyOp { left, right, .. }
        | Expr::AllOp { left, right, .. }
        | Expr::IsDistinctFrom(left, right)
        | Expr::IsNotDistinctFrom(left, right) => vec![left, right],
        Expr::UnaryOp { expr: inner, .. }
        | Expr::Nested(inner)
        | Expr::Cast { expr: inner, .. }
        | Expr::IsNull(inner)
        | Expr::IsNotNull(inner)
        | Expr::IsTrue(inner)
        | Expr::IsNotTrue(inner)
        | Expr::IsFalse(inner)
        | Expr::IsNotFalse(inner)
        | Expr::Collate { expr: inner, .. } => vec![inner],
        Expr::InList { expr: operand, list, .. } => {
            std::iter::once(operand.as_ref()).chain(list.iter()).collect()
        }
        Expr::Between { expr: operand, low, high, .. } => vec![operand, low, high],
        Expr::Like { expr: operand, pattern, .. }
        | Expr::ILike { expr: operand, pattern, .. }
        | Expr::SimilarTo { expr: operand, pattern, .. } => vec![operand, pattern],
        Expr::Tuple(items) => items.iter().collect(),
        Expr::Case { operand, conditions, results, else_result } => operand
            .iter()
            .map(AsRef::as_ref)
            .chain(else_result.iter().map(AsRef::as_ref))
            .chain(conditions.iter())
            .chain(results.iter())
            .collect(),
        Expr::Function(function) => match &function.args {
            sqlparser::ast::FunctionArguments::List(list) => list
                .args
                .iter()
                .filter_map(|argument| {
                    let (FunctionArg::Named { arg, .. }
                    | FunctionArg::ExprNamed { arg, .. }
                    | FunctionArg::Unnamed(arg)) = argument;
                    match arg {
                        FunctionArgExpr::Expr(inner) => Some(inner),
                        _ => None,
                    }
                })
                .collect(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// The first protected column an expression references, however deeply.
fn protected_reference(expr: &Expr, scope: &TableScope<'_>) -> Option<String> {
    if column_ref(scope, expr).is_some() {
        return column_name(expr);
    }
    expr_operands(expr).into_iter().find_map(|child| protected_reference(child, scope))
}

/// A projection item that computes over a protected column rather than
/// selecting it directly.
///
/// PostgreSQL fills `table_oid` and `attnum` in a `RowDescription` only for a
/// *direct* base-table column reference. Wrap the column in anything at all —
/// `email::text`, `ccnum || ''`, `coalesce(email, '')` — and the field arrives
/// as `(0, 0)`, which the read path matches against nothing and relays
/// untouched. For a mask-only column that hands back the very value the mask
/// exists to hide; for an encrypted one it hands back the raw stored form.
///
/// The read path cannot recover from this on its own: an expression output is
/// named `?column?` unless the client aliases it, so there is nothing left to
/// match on. The statement, however, still says plainly which column is being
/// computed over, so the decision is made here while that is still knowable.
fn computed_protected_column<'a>(
    item: &'a SelectItem,
    scope: &TableScope<'_>,
) -> Option<(String, &'a Expr)> {
    let expr = match item {
        SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => expr,
        SelectItem::QualifiedWildcard(..) | SelectItem::Wildcard(_) => return None,
    };
    // A bare column reference is the case the read path handles correctly.
    if column_ref(scope, expr).is_some() {
        return None;
    }
    Some((protected_reference(expr, scope)?, expr))
}

fn column_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Identifier(ident) => Some(normalize(ident)),
        Expr::CompoundIdentifier(idents) => idents.last().map(normalize),
        _ => None,
    }
}

/// The protected column an unhandled predicate is about and whether it is
/// searchable, if any. Only the operands of the predicate are inspected — a
/// protected column buried in a subquery belongs to that subquery's own
/// traversal.
///
/// Every protected column qualifies, not only the searchable ones. What makes
/// an unrewritten predicate wrong is that the *stored form is not the
/// plaintext*, which is true of `encrypt` without `searchable`, of `fpe` and
/// of `token` just as much as of a searchable column — the searchable ones
/// are merely the subset the rewriter can also *fix*. Mask-only columns are
/// not protected here at all: [`WriteCatalog::new`] skips columns with no
/// transform, so they never enter the scope and their predicates are correct
/// as written.
///
/// `IS NULL` and `IS NOT NULL` are deliberately absent: nullness survives
/// sealing exactly. [`QueryRewriter::seal_expr`] returns early on a NULL
/// literal and Bind leaves a NULL parameter untouched, so a NULL in a
/// protected column is stored as SQL NULL and a non-NULL as a non-NULL
/// envelope. `col IS NULL` therefore returns exactly the rows the client
/// meant — no blind index is needed and none would help, so reporting it as
/// an [`Unprotected`] site would refuse working SQL under `reject` and dilute
/// the warning stream under `warn`. `IS DISTINCT FROM` is *not* exempt: it
/// compares against the stored form like any other operator.
fn protected_operand(expr: &Expr, scope: &TableScope<'_>) -> Option<(String, bool)> {
    predicate_operands(expr)?.into_iter().find_map(|operand| protected_column(operand, scope))
}

/// The operands of an unhandled predicate — the positions a column reference
/// can occupy such that the comparison is *about* that column. `None` for an
/// expression that is not a comparison at all.
fn predicate_operands(expr: &Expr) -> Option<[&Expr; 2]> {
    match expr {
        Expr::BinaryOp { left, right, .. }
        | Expr::AnyOp { left, right, .. }
        | Expr::AllOp { left, right, .. } => Some([left, right]),
        Expr::InList { expr, .. }
        | Expr::InSubquery { expr, .. }
        | Expr::Between { expr, .. }
        | Expr::Like { expr, .. }
        | Expr::ILike { expr, .. }
        | Expr::SimilarTo { expr, .. }
        | Expr::IsDistinctFrom(expr, _)
        | Expr::IsNotDistinctFrom(expr, _) => Some([expr, expr]),
        _ => None,
    }
}

/// The name of a predicate operand that matches a protected column in more
/// than one relation in scope.
fn ambiguous_operand(expr: &Expr, scope: &TableScope<'_>) -> Option<String> {
    predicate_operands(expr)?.into_iter().find_map(|operand| ambiguous_column(operand, scope))
}

/// The same for one operand, seeing through a row constructor exactly as
/// [`protected_column`] does.
fn ambiguous_column(operand: &Expr, scope: &TableScope<'_>) -> Option<String> {
    if let Expr::Tuple(items) = operand {
        return items.iter().find_map(|item| ambiguous_column(item, scope));
    }
    match resolve_column(scope, operand) {
        ColumnResolution::Ambiguous => column_name(operand),
        ColumnResolution::One(_) | ColumnResolution::Unknown => None,
    }
}

/// The first protected column an operand names, seeing through a row
/// constructor.
///
/// Row-wise `(a, b) IN (...)` puts an [`Expr::Tuple`] where a column
/// reference would normally be. Without this the tuple resolves to no
/// transform at all, so the predicate was neither rewritten nor reported —
/// the same silent no-match this module exists to prevent, just reached by a
/// different syntax.
fn protected_column(operand: &Expr, scope: &TableScope<'_>) -> Option<(String, bool)> {
    if let Expr::Tuple(items) = operand {
        return items.iter().find_map(|item| protected_column(item, scope));
    }
    let transform = column_ref(scope, operand)?;
    Some((column_name(operand)?, transform.supports_search()))
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
) -> Result<(), Rejection> {
    if let Expr::Value(Value::Placeholder(placeholder)) = unwrap_casts(value) {
        let Some(index) = placeholder_index(placeholder) else {
            return Err(Error::Wire(dbsec_core::Error::Malformed).into());
        };
        record_param(params, index, ParamAction::SearchIndex(transform.clone()))?;
        return Ok(());
    }
    let Some(plaintext) = literal_plaintext(value, transform.wire()) else {
        return Err(Error::Wire(dbsec_core::Error::Malformed).into());
    };
    let Some(token) = transform.search_index(&plaintext).map_err(Error::Wire)? else {
        return Err(Error::Wire(dbsec_core::Error::Malformed).into());
    };
    *value = bytea_literal(&token);
    Ok(())
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
fn bytea_literal(value: &[u8]) -> Expr {
    Expr::Value(Value::EscapedStringLiteral(format!("\\x{}", hex::encode(value))))
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
/// double-quoted and a backslash escapes the character after it — in a quoted
/// element *and* in a bare one, which is what `array_in` does and what makes
/// `{a\,b}` one element rather than two. Only a flat, one-dimensional array is
/// accepted — a nested array or an explicit `[1:2]=` dimension prefix falls
/// back rather than being guessed at.
///
/// Getting the escaping wrong here is not a parse failure that shows up as
/// one: a mis-split element re-encodes into a perfectly well-formed `bytea[]`
/// of blind indexes for values nobody ever stored, so the statement quietly
/// returns the wrong rows. That is the outcome [`index_array`] exists to make
/// impossible, so anything this cannot decode faithfully returns `None` and
/// takes the `on_unprotected` path instead of guessing.
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
            // An unquoted element escapes with a backslash exactly as a quoted
            // one does — `array_in` does not restrict escaping to quotes — so
            // `{a\,b}` is the single element `a,b` and not two elements. Scanning
            // to the next raw comma instead would split it there and hand both
            // halves to the blind index, which matches nothing anyone stored.
            let mut value = Vec::new();
            let mut escaped = false;
            // Only *unescaped* trailing whitespace is insignificant; `a\ ` ends
            // in a space that is part of the value.
            let mut trailing_space = 0;
            loop {
                match bytes.get(at) {
                    None | Some(b',') => break,
                    Some(b'\\') => {
                        value.push(*bytes.get(at + 1)?);
                        at += 2;
                        escaped = true;
                        trailing_space = 0;
                    }
                    // An unescaped brace is a nested array, which this does not
                    // handle; an escaped one is just a character.
                    Some(b'{' | b'}') => return None,
                    Some(&byte) => {
                        value.push(byte);
                        at += 1;
                        if byte.is_ascii_whitespace() {
                            trailing_space += 1;
                        } else {
                            trailing_space = 0;
                        }
                    }
                }
            }
            value.truncate(value.len() - trailing_space);
            let unquoted = String::from_utf8(value).ok()?;
            // `NULL` is the null element only unquoted and unescaped: `\N ULL`
            // and `"NULL"` are both the four-character string.
            (escaped || !unquoted.eq_ignore_ascii_case("null")).then_some(unquoted)
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

/// The expression positions of a `SELECT` that can hold a nested query and are
/// not already swept elsewhere.
///
/// `WHERE` and `HAVING` are deliberately absent: they go through
/// `rewrite_predicate`, which sweeps them as part of rewriting them. Listing
/// them here as well would walk each of their subqueries twice.
fn select_expressions(select: &mut Select) -> impl Iterator<Item = &mut Expr> {
    let projection = select.projection.iter_mut().filter_map(|item| match item {
        SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => Some(expr),
        SelectItem::QualifiedWildcard(..) | SelectItem::Wildcard(_) => None,
    });
    let group_by = match &mut select.group_by {
        GroupByExpr::Expressions(exprs, _) => Some(exprs.iter_mut()),
        GroupByExpr::All(_) => None,
    };
    let join_constraints = select.from.iter_mut().flat_map(|table| {
        table.joins.iter_mut().filter_map(|join| join_condition(&mut join.join_operator))
    });
    projection.chain(group_by.into_iter().flatten()).chain(join_constraints)
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
fn literal_plaintext(expr: &Expr, wire: WireForm) -> Option<Vec<u8>> {
    match unwrap_casts(expr) {
        Expr::Value(
            Value::SingleQuotedString(s)
            | Value::EscapedStringLiteral(s)
            | Value::UnicodeStringLiteral(s)
            | Value::NationalStringLiteral(s),
        ) => Some(text_plaintext(s, wire)),
        Expr::Value(Value::DollarQuotedString(s)) => Some(text_plaintext(&s.value, wire)),
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
    let text = &sql[range.clone()];
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return;
    }
    let start = range.start + (text.len() - text.trim_start().len());
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
///
/// Misjudging a tag is not a harmless miss. A rejected candidate advances a
/// single byte, which walks the scan *into* the body, where quoted text is
/// read as SQL: a `;` that is really literal data splits a statement, and a
/// closing `$tag$` is mistaken for an opening one. Either way the ranges stop
/// corresponding to the parsed statements, and the `ranges.len() ==
/// statements.len()` guard in [`reassemble`] is a count check, not an
/// alignment check.
fn skip_dollar_quoted(bytes: &[u8], start: usize) -> Option<usize> {
    let tag_end = bytes[start + 1..]
        .iter()
        .position(|&b| b == b'$')
        .map(|n| start + 1 + n)
        .filter(|end| is_dollar_tag(&bytes[start + 1..*end]));
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

/// PostgreSQL's dollar-quote tag rule: empty (`$$ ... $$`), or an unquoted
/// identifier — a leading byte that is not a digit, then identifier bytes.
/// Digits are legal after the first character, so `$tag1$` opens a body; the
/// previous rule rejected a digit anywhere and mis-lexed it.
///
/// Non-ASCII bytes count as identifier bytes here because PostgreSQL
/// identifiers admit non-ASCII letters. The bias is deliberate: accepting a
/// tag PostgreSQL would not costs only the caller's text-preservation fast
/// path (the ranges stop matching the statement count and everything is
/// re-rendered), while rejecting a real one corrupts the ranges themselves.
fn is_dollar_tag(tag: &[u8]) -> bool {
    match tag.first() {
        None => true,
        Some(&first) if first.is_ascii_digit() => false,
        _ => tag.iter().all(|&b| is_ident_byte(b) || b >= 0x80),
    }
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
    ///
    /// The `to` direction fires for anything the read path protects, the
    /// `from` direction only for what the write path would have sealed — see
    /// [`WriteCatalog::protects_reads`] for why a mask-only table belongs in
    /// the first set and not the second.
    Copy { table: &'a ObjectName, to: bool },
    /// `COPY (query) TO STDOUT` over a protected table. Kept apart from
    /// [`Self::Copy`] because the remedy differs — there is no table to bulk
    /// load differently, only a query to run as an ordinary `SELECT` so its
    /// rows come back as `DataRow` frames the read path can decrypt and mask.
    CopyQuery { table: String },
    /// A statement shape that writes a protected table but is not rewritten.
    Unsupported { table: &'a ObjectName, shape: &'static str },
    /// An ordinary `'…'` literal carrying a backslash, in a session that
    /// turned `standard_conforming_strings` off — so the server and the
    /// proxy's parser no longer read it as the same bytes.
    AmbiguousLiteral { column: &'a str },
    /// A non-literal expression assigned to a protected column.
    UnsupportedValue { column: &'a str, shape: &'static str },
    /// A protected column projected through an expression rather than
    /// selected directly. The result has no table OID, so the read path
    /// cannot recognise it and relays the stored form — or, for a mask-only
    /// column, the plaintext the mask exists to hide.
    ComputedColumn { column: String, shape: &'static str },
    /// A predicate over a searchable column that no index match can express.
    Predicate { column: String, shape: &'static str },
    /// An unqualified name matching a protected column in more than one
    /// relation in scope. Nothing was rewritten, because choosing one of them
    /// would compare against the wrong table's blind index — and an
    /// unrewritten predicate over a protected column matches no row.
    AmbiguousColumn { column: String, shape: &'static str },
    /// A predicate over a protected column that has no equality index at all,
    /// so no rewrite could express it. Kept apart from [`Self::Predicate`]
    /// because the remedy differs: that one is a query to rewrite, this one is
    /// a column to reconfigure.
    UnindexedPredicate { column: String, shape: &'static str },
    /// `search_path` moved off the schema the catalog resolves against.
    SearchPathChanged,
    /// `standard_conforming_strings` was turned off. Sealed values are emitted
    /// in a form that does not depend on it ([`bytea_literal`]), but the
    /// client's own literals are now read one way by PostgreSQL and another by
    /// the proxy's parser — reported here once, and again per literal that the
    /// difference actually reaches ([`Self::AmbiguousLiteral`]).
    EscapeStringsChanged,
    /// An unqualified name that may be a protected table, in a session whose
    /// `search_path` no longer says which schema it resolves to.
    SearchPath(&'a ObjectName),
}

impl Unprotected<'_> {
    /// Emits the site's warning. The wording of the six original passthrough
    /// sites is kept prefix-compatible so log-based alerting keeps matching;
    /// only the fields that carried plaintext (the bound expression, the
    /// parser's message) are gone, replaced by the shape and the parser error
    /// kind. [`Self::Copy`] gained "or masked" once it started firing for
    /// mask-only tables, which carry no encryption to be bypassed.
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
                "COPY on a protected table is not encrypted or masked by the proxy"
            ),
            Self::CopyQuery { table } => tracing::warn!(
                table,
                direction = "to",
                "COPY of a query over a protected table streams its rows as CopyData, which the \
                 read path cannot decrypt or mask"
            ),
            Self::Unsupported { table, shape } => tracing::warn!(
                table = %table,
                shape,
                "statement writes a protected table but is not rewritten; passing through unencrypted"
            ),
            Self::AmbiguousLiteral { column } => tracing::warn!(
                column,
                "string literal contains a backslash and this session turned \
                 standard_conforming_strings off, so the proxy cannot read it the way the \
                 server will; passing through unencrypted"
            ),
            Self::UnsupportedValue { column, shape } => tracing::warn!(
                column,
                shape,
                "unsupported expression for a protected column; passing through unencrypted"
            ),
            Self::ComputedColumn { column, shape } => tracing::warn!(
                column,
                shape,
                "protected column projected through an expression; the result has no table OID, \
                 so the read path cannot decrypt or mask it and will relay the stored value"
            ),
            Self::Predicate { column, shape } => tracing::warn!(
                column,
                shape,
                "unsupported predicate for a searchable column; it will match no rows"
            ),
            Self::AmbiguousColumn { column, shape } => tracing::warn!(
                column,
                shape,
                "unqualified column matches a protected column in more than one relation in \
                 scope, so the predicate cannot be rewritten and will match no rows; qualify \
                 it with its table or alias"
            ),
            Self::UnindexedPredicate { column, shape } => tracing::warn!(
                column,
                shape,
                "predicate over a protected column with no equality index; it will match no rows \
                 because the stored form is not the plaintext. Set searchable = true on this \
                 column to make equality searchable"
            ),
            Self::SearchPathChanged => tracing::warn!(
                "session changed search_path; unqualified names no longer resolve to the \
                 configured schema"
            ),
            Self::EscapeStringsChanged => tracing::warn!(
                "session turned standard_conforming_strings off; a backslash in a string \
                 literal no longer means to PostgreSQL what the proxy reads it as"
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
                "COPY {} protected table {table} bypasses the proxy's encryption and masking",
                if *to { "from" } else { "into" }
            ),
            Self::CopyQuery { table } => format!(
                "COPY of a query reading protected table {table} returns its rows as CopyData, \
                 which cannot be decrypted or masked; run the query as an ordinary SELECT instead"
            ),
            Self::Unsupported { table, shape } => {
                format!("{shape} writing protected table {table} cannot be encrypted")
            }
            Self::AmbiguousLiteral { column } => format!(
                "a value for protected column {column} contains a backslash and this session \
                 turned standard_conforming_strings off, so the proxy cannot read it the way \
                 the server will"
            ),
            Self::UnsupportedValue { column, shape } => format!(
                "protected column {column} was assigned a {shape}, which cannot be encrypted"
            ),
            Self::ComputedColumn { column, shape } => format!(
                "protected column {column} was projected through a {shape}; the result carries no \
                 table identity, so it cannot be decrypted or masked and would be returned in its \
                 stored form; select the column directly instead"
            ),
            Self::Predicate { column, shape } => format!(
                "searchable column {column} was used in a {shape}, which cannot be matched \
                 against its blind index"
            ),
            Self::AmbiguousColumn { column, shape } => format!(
                "column {column} in a {shape} matches a protected column in more than one \
                 relation in scope, so it cannot be resolved to one and the comparison would \
                 match no rows; qualify it with its table or alias"
            ),
            Self::UnindexedPredicate { column, shape } => format!(
                "protected column {column} was used in a {shape}, but it has no equality index, \
                 so the comparison would match no rows; set searchable = true on this column to \
                 make equality searchable"
            ),
            Self::SearchPathChanged => {
                "changing search_path leaves unqualified names resolving to an unknown schema"
                    .to_owned()
            }
            Self::EscapeStringsChanged => {
                "turning standard_conforming_strings off changes what a backslash in a string \
                 literal means, so a value bound to a protected column can no longer be read \
                 the way the server would read it"
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
    use proptest::prelude::*;
    use proptest::test_runner::TestCaseError;

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

    /// The two other transform kinds, which are never searchable: their
    /// stored form is deterministic but it is not the plaintext, so a
    /// predicate over one matches nothing just as an unsearchable `encrypt`
    /// column does.
    fn fpe_transform() -> Arc<dyn FieldTransform> {
        Arc::new(dbsec_core::transform::FpeTransform::new(
            Arc::new(crate::rows::tests::OneKey),
            "public.users.email".to_owned(),
            true,
        ))
    }

    fn token_transform() -> Arc<dyn FieldTransform> {
        Arc::new(dbsec_core::transform::TokenTransform::new(
            Arc::new(crate::rows::tests::OneKey),
            "public.users.email".to_owned(),
        ))
    }

    /// A catalog holding one column with an arbitrary transform, so the
    /// predicate tests can cover every kind under both policies.
    fn catalog_of(
        transform: Arc<dyn FieldTransform>,
        searchable: bool,
        on_unprotected: OnUnprotected,
    ) -> Arc<WriteCatalog> {
        Arc::new(WriteCatalog::new(&[column("email", transform, searchable)], on_unprotected))
    }

    /// Two protected tables that both carry a searchable `email`, so an
    /// unqualified `email` in a query joining them resolves to neither.
    fn ambiguous_catalog(on_unprotected: OnUnprotected) -> Arc<WriteCatalog> {
        let mut accounts = column("email", transform(true), true);
        accounts.table = "accounts".into();
        let users = column("email", transform(true), true);
        Arc::new(WriteCatalog::new(&[users, accounts], on_unprotected))
    }

    /// A table whose only protection is a read-path mask. Its column has no
    /// transform, so nothing on the write path seals it and its stored form is
    /// the plaintext — the mask applied on the way out is all that hides it.
    fn mask_only_catalog(on_unprotected: OnUnprotected) -> Arc<WriteCatalog> {
        Arc::new(WriteCatalog::new(
            &[ProtectedColumn {
                schema: "public".into(),
                table: "notes".into(),
                column: "body".into(),
                transform: None,
                searchable: false,
                readable: false,
                mask: Some(dbsec_core::mask::MaskSpec {
                    keep_first: 1,
                    keep_last: 0,
                    mask_with: '*',
                }),
            }],
            on_unprotected,
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
            FrameAction::Reply(_) | FrameAction::RefuseAndClose(_) => {
                panic!("refused: {sql}")
            }
        }
    }

    /// The ErrorResponse text of a refused frame.
    fn refusal(action: &FrameAction) -> String {
        let FrameAction::Reply(bytes) = action else { panic!("expected a refusal") };
        assert_eq!(bytes[0], b'E', "first frame is an ErrorResponse");
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// How a sealed BYTEA value appears in rewritten SQL: the escape-string
    /// literal [`bytea_literal`] emits, with its backslash doubled.
    const SEALED_PREFIX: &str = r"E'\\x";

    fn sealed_literal(value: &[u8]) -> String {
        format!("{SEALED_PREFIX}{}'", hex::encode(value))
    }

    /// Extracts the sealed hex literal out of a rewritten statement and
    /// opens it.
    fn open_hex_literal(sql: &str, searchable: bool) -> Vec<u8> {
        let stored = hex::decode(sealed_hex(sql).expect("hex literal")).unwrap();
        transform(searchable).open(&stored).unwrap().expect("opens")
    }

    /// The hex digits of the first sealed literal in a rewritten statement.
    fn sealed_hex(sql: &str) -> Option<&str> {
        let start = sql.find(SEALED_PREFIX)? + SEALED_PREFIX.len();
        let end = sql[start..].find('\'')? + start;
        Some(&sql[start..end])
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
        assert!(sql.contains(&sealed_literal(&expected)), "{sql}");
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
        assert!(sql.contains(&sealed_literal(&expected)), "{sql}");

        // Aliased and AND-nested references rewrite too; DELETE works.
        let sql = rewritten_query(
            &mut rewriter,
            "DELETE FROM users u WHERE u.id > 4 AND (u.email = 'bob@x.io' OR u.email = 'c@y.io')",
        )
        .expect("rewritten");
        assert!(!sql.contains("bob@x.io") && !sql.contains("c@y.io"), "{sql}");
        assert_eq!(sql.matches("SUBSTRING(u.email FROM 1 FOR 32)").count(), 2, "{sql}");
    }

    /// A parenthesised join is one `TableFactor::NestedJoin` holding the whole
    /// join, not the two `Table` factors the same query has without the
    /// parentheses. The scope walk stopped at the top level, so every
    /// protected table inside them was invisible: the equality was relayed
    /// comparing the client's plaintext against the stored
    /// `blind_index || envelope`, which matches no row and reads as "no such
    /// user" — reached by adding one pair of parentheses.
    #[test]
    fn a_parenthesized_join_puts_its_protected_tables_in_scope() {
        use crate::rows::tests::INDEX_KEY;

        let mut rewriter = rewriter(catalog(true));
        let expected = blind_index::compute(&INDEX_KEY, b"alice@example.com");

        for sql in [
            // The enclosing predicate.
            "SELECT 1 FROM (users JOIN orders ON orders.id = users.id) \
             WHERE users.email = 'alice@example.com'",
            // A join constraint *inside* the parentheses.
            "SELECT 1 FROM (orders JOIN users ON users.email = 'alice@example.com')",
            // A derived table nested inside them, with its own predicate.
            "SELECT 1 FROM (orders JOIN (SELECT id FROM users WHERE \
             email = 'alice@example.com') s ON s.id = orders.id)",
            // Nested twice over, and reached through an UPDATE's FROM rather
            // than a SELECT's.
            "UPDATE orders SET total = 1 FROM ((users JOIN accounts ON accounts.id = users.id)) \
             WHERE users.email = 'alice@example.com'",
        ] {
            let rewritten = rewritten_query(&mut rewriter, sql).unwrap_or_else(|| {
                panic!("relayed verbatim instead of rewritten: {sql}");
            });
            assert!(!rewritten.contains("alice@example.com"), "{sql}: {rewritten}");
            assert!(rewritten.contains(&sealed_literal(&expected)), "{sql}: {rewritten}");
        }
    }

    /// The other half of the same gap: a shape no blind index can answer, over
    /// a table only the parenthesised join brings into scope, has to reach
    /// [`QueryRewriter::unprotected`] — otherwise `reject` does not fail closed
    /// for this syntax and the comparison is relayed to match nothing.
    #[test]
    fn an_unrewritable_predicate_inside_a_parenthesized_join_is_refused() {
        let mut strict = rewriter(strict_catalog(true));
        for sql in [
            "SELECT 1 FROM (users JOIN orders ON orders.id = users.id) \
             WHERE users.email LIKE 'a%'",
            "SELECT 1 FROM (orders JOIN users ON users.email > 'a')",
            "SELECT 1 FROM (orders JOIN (SELECT id FROM users WHERE email LIKE 'a%') s \
             ON s.id = orders.id)",
        ] {
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(
                refusal(&action).contains("searchable column email"),
                "{sql}: {}",
                refusal(&action)
            );
        }
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
    ///
    /// The refusal is statement-level: this is valid client SQL, and killing
    /// the session over it left the client with a bare connection reset — and
    /// a pooled retry that took the next connection with it.
    #[test]
    fn a_placeholder_in_two_protected_roles_is_refused_rather_than_transformed_twice() {
        let mut extended = rewriter(catalog(true));
        let parse = pgwire::encode_parse(
            b"u",
            b"UPDATE users SET email = $1 WHERE email = $1",
            &0i16.to_be_bytes(),
        );
        let action = extended.on_frame(b'P', &parse).unwrap();
        assert!(refusal(&action).contains("placeholder $1"), "{}", refusal(&action));
        // The batch is discarded up to Sync, which the proxy answers itself,
        // and the session is usable afterwards.
        assert_eq!(extended.on_frame(b'B', b"").unwrap(), FrameAction::Reply(Vec::new()));
        let FrameAction::Reply(sync) = extended.on_frame(b'S', b"").unwrap() else {
            panic!("Sync must be answered")
        };
        assert_eq!(sync[0], b'Z');
        assert!(matches!(
            extended.on_frame(b'Q', &query_frame("SELECT 1")).unwrap(),
            FrameAction::Relay
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
        assert!(sql.contains(&sealed_literal(&index)), "{sql}");
    }

    /// Two protected columns of one table under *different* transforms, so a
    /// placeholder feeding both cannot be satisfied by one value on the wire.
    fn two_column_catalog(on_unprotected: OnUnprotected) -> Arc<WriteCatalog> {
        Arc::new(WriteCatalog::new(
            &[
                column("email", transform(false), false),
                column("backup_email", transform(false), false),
            ],
            on_unprotected,
        ))
    }

    /// `INSERT INTO users (email, backup_email) VALUES ($1, $1)` is valid
    /// client SQL that the Bind cannot carry, so it is refused at statement
    /// level in both protocols — and under *both* `on_unprotected` settings,
    /// because there is no "warn and relay" answer: relaying it would seal one
    /// value and then re-seal or blind-index the ciphertext.
    #[test]
    fn one_placeholder_for_two_protected_columns_is_refused_under_both_policies() {
        const SQL: &str = "INSERT INTO users (email, backup_email) VALUES ($1, $1)";
        for policy in [OnUnprotected::Warn, OnUnprotected::Reject] {
            // Simple protocol: nothing reached the backend, so the proxy owes
            // the ReadyForQuery itself.
            let mut simple = rewriter(two_column_catalog(policy));
            let action = simple.on_frame(b'Q', &query_frame(SQL)).unwrap();
            let text = refusal(&action);
            assert!(text.contains("placeholder $1"), "{text}");
            let FrameAction::Reply(bytes) = &action else { unreachable!() };
            assert_eq!(bytes[bytes.len() - 1], b'I', "the refusal answers the batch too");
            assert!(
                matches!(
                    simple.on_frame(b'Q', &query_frame("SELECT 1")).unwrap(),
                    FrameAction::Relay
                ),
                "the session stays usable"
            );

            // Extended protocol: refused at Parse, and the rest of the batch
            // is discarded up to Sync exactly as any other refused Parse is.
            let mut extended = rewriter(two_column_catalog(policy));
            let parse = pgwire::encode_parse(b"i", SQL.as_bytes(), &0i16.to_be_bytes());
            let action = extended.on_frame(b'P', &parse).unwrap();
            assert!(refusal(&action).contains("placeholder $1"));
            assert_eq!(extended.on_frame(b'E', b"").unwrap(), FrameAction::Reply(Vec::new()));
            let FrameAction::Reply(sync) = extended.on_frame(b'S', b"").unwrap() else {
                panic!("Sync must be answered")
            };
            assert_eq!(sync[0], b'Z');
        }
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
        for literal in sql.split(SEALED_PREFIX).skip(1) {
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

    /// A subquery in an *expression* position carries its own FROM, so the
    /// searchable equality inside it has to be rewritten against that scope.
    /// The outer statement mentions no protected column at all, which is why
    /// nothing signalled: the predicate simply compared plaintext against the
    /// stored form and matched nothing.
    #[test]
    fn searchable_equality_inside_an_operand_subquery_is_rewritten() {
        for sql in [
            // Scalar subquery as an operand.
            "SELECT * FROM orders WHERE user_id = \
             (SELECT id FROM users WHERE email = 'alice@secret.test')",
            // EXISTS, which was not even an arm in the predicate walk.
            "SELECT * FROM orders o WHERE EXISTS \
             (SELECT 1 FROM users u WHERE u.email = 'alice@secret.test')",
            // The body of IN (SELECT ...).
            "SELECT * FROM orders WHERE user_id IN \
             (SELECT id FROM users WHERE email = 'alice@secret.test')",
            // Projection position.
            "SELECT (SELECT id FROM users WHERE email = 'alice@secret.test') FROM orders",
            // Nested two deep, to pin that the recursion is not one level.
            "SELECT * FROM orders WHERE user_id IN (SELECT id FROM t WHERE x IN \
             (SELECT id FROM users WHERE email = 'alice@secret.test'))",
            // Inside a function argument and a CASE.
            "SELECT coalesce((SELECT id FROM users WHERE email = 'alice@secret.test'), 0) FROM t",
            "SELECT CASE WHEN EXISTS \
             (SELECT 1 FROM users WHERE email = 'alice@secret.test') THEN 1 ELSE 0 END FROM t",
            // ORDER BY and HAVING.
            "SELECT id FROM orders ORDER BY \
             (SELECT id FROM users WHERE email = 'alice@secret.test')",
            "SELECT count(*) FROM orders HAVING count(*) > \
             (SELECT id FROM users WHERE email = 'alice@secret.test')",
        ] {
            let mut rewriter = rewriter(catalog(true));
            let rewritten = rewritten_query(&mut rewriter, sql)
                .unwrap_or_else(|| panic!("subquery was never traversed: {sql}"));
            assert!(
                rewritten.to_ascii_uppercase().contains("SUBSTRING"),
                "the inner equality was not indexed: {rewritten}"
            );
            assert!(
                !rewritten.contains("alice@secret.test"),
                "plaintext still compared against the stored form: {rewritten}"
            );
        }
    }

    /// The amplifier that makes "matches nothing" unsafe rather than merely
    /// wrong: an empty subquery result turns `NOT IN (empty)` into true for
    /// every row, so the DELETE takes the whole table instead of sparing the
    /// rows the operator meant to keep.
    #[test]
    fn the_not_in_subquery_mass_delete_amplifier_is_rewritten() {
        let sql = "DELETE FROM t WHERE id NOT IN \
                   (SELECT id FROM users WHERE email = 'keep@secret.test')";

        let mut rewriter = rewriter(catalog(true));
        let rewritten = rewritten_query(&mut rewriter, sql).expect("the subquery was traversed");
        assert!(rewritten.to_ascii_uppercase().contains("SUBSTRING"), "not indexed: {rewritten}");
        assert!(!rewritten.contains("keep@secret.test"), "plaintext survived: {rewritten}");

        // The rewritten predicate must still be a NOT IN over the same shape,
        // so the statement's meaning is unchanged apart from the index match.
        assert!(rewritten.contains("NOT IN"), "the predicate shape changed: {rewritten}");
    }

    /// A subquery predicate that cannot be expressed as an index match is a
    /// site like any other — reaching it through a subquery must not lose the
    /// signal, or `reject` would pass exactly the queries it exists to catch.
    #[test]
    fn an_unrewritable_predicate_inside_a_subquery_is_still_refused() {
        for sql in [
            "SELECT * FROM orders WHERE user_id = \
             (SELECT id FROM users WHERE email LIKE 'a%')",
            "SELECT * FROM orders WHERE EXISTS \
             (SELECT 1 FROM users WHERE email > 'a@b.io')",
            "SELECT (SELECT id FROM users WHERE email = lower('a@b.io')) FROM t",
        ] {
            let mut strict = rewriter(strict_catalog(true));
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(
                refusal(&action).contains("searchable column email"),
                "{sql}\n  got: {}",
                refusal(&action)
            );
        }
    }

    /// Row-wise `(a, b) IN (...)` puts a row constructor where a column
    /// reference would be, so no single transform covers it. It cannot be
    /// rewritten, but relaying it silently is the same no-match failure.
    #[test]
    fn a_row_wise_in_list_over_a_searchable_column_is_signalled() {
        let sql = "SELECT id FROM users WHERE (email, id) IN (('a@b.io', 1), ('c@d.io', 2))";

        let mut permissive = rewriter(catalog(true));
        assert!(rewritten_query(&mut permissive, sql).is_none(), "nothing to rewrite");

        let mut strict = rewriter(strict_catalog(true));
        let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
        assert!(refusal(&action).contains("searchable column email"), "{}", refusal(&action));
    }

    /// The traversal must not turn subqueries over unprotected columns into
    /// refusals, nor rewrite anything in them.
    #[test]
    fn subqueries_over_unprotected_columns_are_left_alone() {
        let mut strict = rewriter(strict_catalog(true));
        for sql in [
            "SELECT * FROM orders WHERE user_id = (SELECT id FROM other WHERE name = 'x')",
            "SELECT * FROM orders WHERE EXISTS (SELECT 1 FROM other WHERE id > 4)",
            "SELECT (SELECT id FROM other WHERE name = 'x') FROM t",
        ] {
            assert!(
                matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
                "{sql}"
            );
        }
    }

    /// PostgreSQL fills a RowDescription's table OID only for a direct column
    /// reference, so anything wrapped around a protected column comes back as
    /// `(0, 0)` and the read path cannot act on it. For a mask-only column
    /// that returns the value the mask exists to hide; for an encrypted one it
    /// returns the raw stored form. The statement still names the column, so
    /// the decision is made here.
    #[test]
    fn a_protected_column_computed_over_in_the_projection_is_signalled() {
        for sql in [
            "SELECT email || '' FROM users",
            "SELECT email::text FROM users",
            "SELECT coalesce(email, '') FROM users",
            "SELECT lower(email) FROM users",
            "SELECT max(email) FROM users",
            "SELECT CASE WHEN id > 1 THEN email ELSE '' END FROM users",
            // Aliasing it back to the column's own name changes nothing.
            "SELECT email || '' AS email FROM users",
        ] {
            let mut strict = rewriter(strict_catalog(false));
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            let refusal = refusal(&action);
            assert!(
                refusal.contains("projected through") && refusal.contains("email"),
                "{sql}\n  got: {refusal}"
            );
        }
    }

    /// The shapes that must keep working: selecting the column directly is
    /// exactly what the read path handles, and expressions over other columns
    /// are none of this check's business.
    #[test]
    fn selecting_a_protected_column_directly_is_not_a_computed_column() {
        let mut strict = rewriter(strict_catalog(false));
        for sql in [
            "SELECT email FROM users",
            "SELECT u.email FROM users u",
            "SELECT email AS e FROM users",
            "SELECT * FROM users",
            "SELECT id + 1 FROM users",
            "SELECT lower(name) FROM users",
            "SELECT count(*) FROM users",
            "SELECT lower(email) FROM other",
        ] {
            assert!(
                matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
                "{sql}"
            );
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

    /// The query-source form of the same statement. `COPY (SELECT email FROM
    /// users) TO STDOUT` is a `CopySource::Query`, so the classifier — which
    /// looked at `CopySource::Table` only — never saw it, and its rows leave
    /// as `CopyData` frames the read path relays verbatim. The table form was
    /// refused under `reject` and this one was not, which is the strict
    /// setting being escaped by rewriting the statement.
    #[test]
    fn a_query_source_copy_out_over_a_protected_table_is_a_site_in_both_modes() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let statements = [
            "COPY (SELECT email FROM users) TO STDOUT",
            "COPY (SELECT * FROM users WHERE id = 1) TO STDOUT",
            // The shapes a walk of the top-level FROM clause alone would miss.
            "COPY (SELECT e FROM (SELECT email AS e FROM users) s) TO STDOUT",
            "COPY (WITH c AS (SELECT email FROM users) SELECT * FROM c) TO STDOUT",
            "COPY (SELECT id FROM other UNION ALL SELECT id FROM users) TO STDOUT",
            "COPY (SELECT * FROM (other JOIN users ON other.id = users.id)) TO STDOUT",
        ];

        let mut strict = rewriter(strict_catalog(false));
        for sql in statements {
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(
                refusal(&action).contains("protected table users"),
                "{sql}: {}",
                refusal(&action)
            );
        }

        // `COPY (TABLE users) TO STDOUT` is the one query source sqlparser
        // 0.53 cannot parse (`parse_as_table` overruns the closing paren), so
        // it lands on the unparseable-SQL site instead — refused all the same,
        // which is what keeps the parser quirk from being a hole.
        let action = strict.on_frame(b'Q', &query_frame("COPY (TABLE users) TO STDOUT")).unwrap();
        assert!(refusal(&action).contains("could not be parsed"), "{}", refusal(&action));

        // Under warn the same statements relay, each with one warning naming
        // the table — and a query over nothing protected stays silent.
        let _capture = crate::log_capture();
        let captured = CapturedEvents::default();
        let subscriber = tracing_subscriber::registry().with(captured.clone());
        tracing::subscriber::with_default(subscriber, || {
            let mut permissive = rewriter(catalog(false));
            for sql in statements.iter().chain(&["COPY (SELECT id FROM other) TO STDOUT"]) {
                assert!(
                    matches!(
                        permissive.on_frame(b'Q', &query_frame(sql)).unwrap(),
                        FrameAction::Relay
                    ),
                    "{sql}"
                );
            }
        });

        let events = captured.0.lock().expect("captured events");
        assert_eq!(events.len(), statements.len(), "one warning each: {events:?}");
        for event in events.iter() {
            assert!(event.contains("read path cannot decrypt or mask"), "{event}");
            assert!(event.contains("users"), "{event}");
        }
    }

    /// A table protected only by a read-path mask never enters
    /// [`WriteCatalog`]: a mask-only column has no transform, and that catalog
    /// exists to say what a *write* must seal. Right for writes, and exactly
    /// wrong for `COPY … TO`, whose rows leave as `CopyData` frames the read
    /// path relays verbatim — the stored value *is* the plaintext, so the
    /// statement hands the client the very value the mask exists to hide.
    /// This is the sharpest form of the COPY leak: an encrypted column at
    /// least leaves as ciphertext.
    #[test]
    fn a_mask_only_table_is_a_copy_out_site_in_both_forms_and_both_modes() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let out = ["COPY notes TO STDOUT", "COPY (SELECT body FROM notes) TO STDOUT"];

        let mut strict = rewriter(mask_only_catalog(OnUnprotected::Reject));
        for sql in out {
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(refusal(&action).contains("notes"), "{sql}: {}", refusal(&action));
        }

        // The write direction is deliberately not a site. A mask-only column
        // is stored in plaintext, so a plaintext write to it is the correct
        // outcome — flagging one would be a false refusal, which is what keeps
        // operators off the fail-closed setting.
        for sql in [
            "COPY notes FROM STDIN",
            "COPY notes (body) FROM STDIN",
            "INSERT INTO notes (body) VALUES ('plaintext')",
            "UPDATE notes SET body = 'plaintext' WHERE body = 'x'",
        ] {
            assert!(
                matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
                "{sql}"
            );
        }

        // Under warn the reads relay with one warning each, naming the table,
        // and the write stays silent.
        let _capture = crate::log_capture();
        let captured = CapturedEvents::default();
        let subscriber = tracing_subscriber::registry().with(captured.clone());
        tracing::subscriber::with_default(subscriber, || {
            let mut permissive = rewriter(mask_only_catalog(OnUnprotected::Warn));
            for sql in out.iter().chain(&["COPY notes FROM STDIN"]) {
                assert!(
                    matches!(
                        permissive.on_frame(b'Q', &query_frame(sql)).unwrap(),
                        FrameAction::Relay
                    ),
                    "{sql}"
                );
            }
        });

        let events = captured.0.lock().expect("captured events");
        assert_eq!(events.len(), out.len(), "one warning per read, none for the write: {events:?}");
        for event in events.iter() {
            assert!(event.contains("notes"), "{event}");
        }
    }

    /// A searchable predicate inside `COPY (query) TO STDOUT` is an ordinary
    /// predicate: left alone it compares the client's plaintext against the
    /// stored `blind_index || envelope`, matching no row — and "no rows" is
    /// indistinguishable from "no such user". Under `reject` the leak site
    /// refuses the statement before anything is rendered; under `warn` it
    /// relays, so the predicate has to be rewritten for the relayed text to
    /// mean what the client wrote.
    #[test]
    fn a_searchable_predicate_inside_a_copy_query_is_rewritten_or_reported() {
        use crate::rows::tests::INDEX_KEY;

        let sql = "COPY (SELECT id FROM users WHERE email = 'alice@example.com') TO STDOUT";

        let mut strict = rewriter(strict_catalog(true));
        let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
        assert!(refusal(&action).contains("protected table users"), "{}", refusal(&action));

        let _capture = crate::log_capture();
        let mut permissive = rewriter(catalog(true));
        let rewritten = rewritten_query(&mut permissive, sql).expect("rewritten");
        let expected = blind_index::compute(&INDEX_KEY, b"alice@example.com");
        assert!(!rewritten.contains("alice@example.com"), "{rewritten}");
        assert!(rewritten.contains("SUBSTRING(email FROM 1 FOR 32)"), "{rewritten}");
        assert!(rewritten.contains(&sealed_literal(&expected)), "{rewritten}");
        assert!(
            rewritten.starts_with("COPY (") && rewritten.ends_with(") TO STDOUT"),
            "still a COPY: {rewritten}"
        );

        // A predicate the blind index cannot answer, in a subquery the
        // leak-site walk does not reach, is raised as its own site instead of
        // being relayed to match nothing.
        let mut strict = rewriter(strict_catalog(true));
        let action = strict
            .on_frame(
                b'Q',
                &query_frame(
                    "COPY (SELECT id FROM other WHERE id IN \
                     (SELECT id FROM users WHERE email LIKE 'a%')) TO STDOUT",
                ),
            )
            .unwrap();
        assert!(refusal(&action).contains("searchable column email"), "{}", refusal(&action));

        // `COPY ... FROM STDIN` is never re-rendered: only the `TO` direction
        // has a query source to rewrite, so nothing marks it changed and
        // `reassemble` keeps its source text byte for byte — including when a
        // statement beside it in the same batch *is* rewritten. Re-rendering
        // it would drop it back to text the wire has no form for.
        let mut permissive = rewriter(catalog(true));
        assert!(
            matches!(
                permissive.on_frame(b'Q', &query_frame("COPY users (email) FROM STDIN")).unwrap(),
                FrameAction::Relay
            ),
            "COPY FROM STDIN relayed verbatim"
        );
        let batch = rewritten_query(
            &mut permissive,
            "UPDATE users SET email = 'bob@x.io'; COPY users (email) FROM STDIN",
        )
        .expect("rewritten");
        assert!(batch.ends_with("COPY users (email) FROM STDIN"), "{batch}");
        assert!(!batch.contains("bob@x.io"), "{batch}");
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
            assert_eq!(transform(false).open(&stored).unwrap().unwrap(), expected);
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

    /// `set_config` is the function spelling of `SET`, and it arrives as an
    /// ordinary `SELECT` — nothing in the parsed statement marks it as a
    /// session change. Missing it is not a plaintext leak but a silent
    /// mis-seal: the value is sealed for `public.users` while the row lands in
    /// `tenant7.users`, where the read path can never find it again.
    #[test]
    fn set_config_moves_search_path_the_same_way_set_does() {
        for sql in [
            "SELECT set_config('search_path', 'tenant7', false)",
            "SELECT pg_catalog.set_config('search_path', 'tenant7', false)",
            "SELECT set_config('SEARCH_PATH', 'tenant7', false)",
            // A list that no longer starts at `public`.
            "SELECT set_config('search_path', 'tenant7, public', false)",
            // A setting name the proxy cannot read could be `search_path`.
            "SELECT set_config($1, $2, false)",
            // Nested anywhere in the statement, not just the projection.
            "SELECT id FROM users WHERE id = (SELECT set_config('search_path', 'x', false))::int",
        ] {
            let mut rewriter = rewriter(catalog(false));
            assert!(rewritten_query(&mut rewriter, sql).is_none(), "{sql}");
            assert!(
                rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('a@b.io')")
                    .is_none(),
                "unqualified write was still sealed after: {sql}"
            );
        }
    }

    /// The value still has to be read: `set_config` back to the default leaves
    /// unqualified names resolving to `public`, so the write is sealed.
    #[test]
    fn set_config_back_to_the_default_stays_trusted() {
        let mut rewriter = rewriter(catalog(false));
        assert!(rewritten_query(
            &mut rewriter,
            "SELECT set_config('search_path', '\"$user\", public', false)"
        )
        .is_none());
        let sql = rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('a@b.io')")
            .expect("rewritten");
        assert!(!sql.contains("a@b.io"), "{sql}");
    }

    /// Reading the whole batch's tokens up front is what makes `SET SCHEMA`
    /// and `set_config` visible at all, but a move still belongs only to the
    /// statements after it. Flattening the batch would let a `SET` at its end
    /// retroactively unseal the write in front of it — a plaintext write under
    /// the default `warn`, for SQL the server executes in the other order.
    #[test]
    fn a_search_path_move_does_not_reach_back_over_the_writes_before_it() {
        let mut rewriter = rewriter(catalog(false));
        let sql = rewritten_query(
            &mut rewriter,
            "INSERT INTO users (email) VALUES ('a@b.io'); SET search_path TO tenant7",
        )
        .expect("rewritten");
        assert!(!sql.contains("a@b.io"), "the write before the move was not sealed: {sql}");

        // And it holds for everything after it, in the same batch or a later
        // one.
        assert!(
            rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('c@d.io')").is_none(),
            "the move did not stick"
        );
    }

    /// The other half of the same rule: a move does reach the statements that
    /// follow it inside its own batch.
    #[test]
    fn a_search_path_move_covers_the_writes_after_it_in_the_same_batch() {
        let mut rewriter = rewriter(catalog(false));
        assert!(
            rewritten_query(
                &mut rewriter,
                "SET search_path TO tenant7; INSERT INTO users (email) VALUES ('e@f.io')",
            )
            .is_none(),
            "a write after the move in the same batch must not be sealed"
        );
    }

    /// sqlparser 0.53 cannot parse `SET SCHEMA` at all, so it reaches the
    /// server as unparseable SQL and, under `warn`, is relayed. Reading the
    /// token stream rather than the AST is what keeps it tracked anyway.
    #[test]
    fn set_schema_moves_search_path_even_though_it_does_not_parse() {
        let mut rewriter = rewriter(catalog(false));
        assert!(parse_sql("SET SCHEMA 'tenant7'").is_err(), "the premise of this test");
        assert!(rewritten_query(&mut rewriter, "SET SCHEMA 'tenant7'").is_none());
        assert!(
            rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('a@b.io')").is_none(),
            "an unqualified name must not be sealed once SET SCHEMA moved search_path"
        );
    }

    /// `set_config` and `SET SCHEMA` are refused under `reject` exactly as
    /// `SET search_path` is, so an operator who pinned the search_path cannot
    /// have it moved out from under them by a spelling the proxy ignored.
    #[test]
    fn strict_mode_refuses_every_search_path_spelling() {
        for sql in [
            "SET search_path TO tenant7",
            "SET SCHEMA 'tenant7'",
            "SELECT set_config('search_path', 'tenant7', false)",
        ] {
            let mut strict = rewriter(strict_catalog(false));
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(refusal(&action).contains("search_path"), "{sql}");
        }
    }

    /// The word `set_config` inside a string literal or a quoted identifier is
    /// data, not a call: reading tokens rather than the raw text is what keeps
    /// these from refusing working SQL under `reject`.
    #[test]
    fn session_settings_are_not_read_out_of_literals_or_column_names() {
        for sql in [
            "SELECT id FROM users WHERE note = 'set_config(''search_path'', ''x'', false)'",
            "UPDATE audit SET search_path = 'tenant7' WHERE id = 1",
        ] {
            let mut strict = rewriter(strict_catalog(false));
            assert!(
                matches!(
                    strict.on_frame(b'Q', &query_frame(sql)).unwrap(),
                    FrameAction::Relay | FrameAction::Replace(_)
                ),
                "{sql}"
            );
        }
    }

    // --- standard_conforming_strings ---------------------------------------

    /// A sealed BYTEA value goes out as `E'\\x…'`, not `'\x…'`. The plain
    /// spelling is PostgreSQL's hex input syntax only while
    /// `standard_conforming_strings` is on; with it off the server applies
    /// backslash processing first and stores something else entirely. The
    /// escape-string form means the same bytes under either setting.
    #[test]
    fn sealed_bytea_literals_do_not_depend_on_standard_conforming_strings() {
        let mut rewriter = rewriter(catalog(true));
        let sql = rewritten_query(&mut rewriter, "UPDATE users SET email = 'bob@secret.test'")
            .expect("rewritten");
        let hex = sealed_hex(&sql).expect("sealed literal");
        assert!(sql.contains(&format!(r"E'\\x{hex}'")), "{sql}");
        assert!(
            !sql.contains(&format!(r"'\x{hex}'")),
            "a bare hex literal is still emitted: {sql}"
        );

        // The same holds for the blind-index literal a predicate is rewritten
        // to, which is BYTEA whatever the column's own stored form is.
        let sql = rewritten_query(&mut rewriter, "SELECT id FROM users WHERE email = 'a@b.io'")
            .expect("rewritten");
        let index = blind_index::compute(&crate::rows::tests::INDEX_KEY, b"a@b.io");
        assert!(sql.contains(&sealed_literal(&index)), "{sql}");
    }

    /// Turning the setting off is still reported: the proxy's own reading of
    /// the *client's* literals diverges from the server's from that point on,
    /// which no choice of output encoding can fix.
    #[test]
    fn turning_standard_conforming_strings_off_is_an_unprotected_site() {
        for sql in [
            "SET standard_conforming_strings = off",
            "SET standard_conforming_strings TO 'off'",
            "SET SESSION standard_conforming_strings = false",
            "SELECT set_config('standard_conforming_strings', 'off', false)",
        ] {
            let mut strict = rewriter(strict_catalog(false));
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(refusal(&action).contains("standard_conforming_strings"), "{sql}");
        }
    }

    /// Under the default `warn` the session carries on, and the write that
    /// follows is still sealed in the setting-independent form.
    #[test]
    fn a_write_after_standard_conforming_strings_off_is_still_sealed_readably() {
        let mut rewriter = rewriter(catalog(false));
        assert!(rewritten_query(&mut rewriter, "SET standard_conforming_strings = off").is_none());
        let sql = rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('a@b.io')")
            .expect("rewritten");
        assert!(sql.contains(SEALED_PREFIX), "{sql}");
        assert_eq!(open_hex_literal(&sql, false), b"a@b.io");
    }

    /// Once the setting is off, a literal that actually carries a backslash is
    /// one the proxy and the server read differently. Sealing it would store
    /// the proxy's reading, which nothing downstream could tell apart from a
    /// correct value, so the literal is reported instead and the data stays
    /// intact. Literals without a backslash mean the same thing either way and
    /// are still sealed.
    #[test]
    fn a_backslash_literal_after_the_setting_moved_is_reported_not_guessed_at() {
        let mut lenient = rewriter(catalog(true));
        assert!(rewritten_query(&mut lenient, "SET standard_conforming_strings = off").is_none());

        assert!(
            rewritten_query(&mut lenient, r"INSERT INTO users (email) VALUES ('a\nb@secret.test')")
                .is_none(),
            "a literal the two sides read differently must not be sealed"
        );
        assert!(
            rewritten_query(&mut lenient, r"SELECT id FROM users WHERE email = 'a\nb@secret.test'")
                .is_none(),
            "nor indexed"
        );

        // No backslash, no disagreement.
        let sql = rewritten_query(&mut lenient, "INSERT INTO users (email) VALUES ('a@b.io')")
            .expect("rewritten");
        assert_eq!(open_hex_literal(&sql, true), b"a@b.io");

        // Under `reject` the setting change is refused outright, so the state
        // this guards against is unreachable in the mode that enforces the
        // invariant.
        let mut strict = rewriter(strict_catalog(true));
        let action =
            strict.on_frame(b'Q', &query_frame("SET standard_conforming_strings = off")).unwrap();
        assert!(refusal(&action).contains("standard_conforming_strings"));
    }

    /// Turning it *on* is the state the proxy already assumes, so it is not a
    /// site at all — a signal that fires on correct SQL stops being read.
    #[test]
    fn turning_standard_conforming_strings_on_is_not_reported() {
        for sql in [
            "SET standard_conforming_strings = on",
            "SET standard_conforming_strings TO true",
            "SET standard_conforming_strings = 1",
        ] {
            let mut strict = rewriter(strict_catalog(false));
            assert!(
                matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
                "{sql}"
            );
        }
    }

    // --- identifier folding ------------------------------------------------

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

    /// A dollar-quote tag follows PostgreSQL's identifier rule, so digits are
    /// legal after the first character. Rejecting them walked the scan into
    /// the quoted body, where a `;` in literal data split the statement and a
    /// closing tag was read as an opening one.
    #[test]
    fn dollar_quote_tags_may_contain_digits() {
        // A `;` inside the body is data, not a separator.
        let sql = "SELECT $tag1$a;b$tag1$";
        let ranges = statement_ranges(sql).expect("splits");
        assert_eq!(ranges.len(), 1, "the ; is inside the quoted body: {ranges:?}");
        assert_eq!(&sql[ranges[0].clone()], sql);

        // Tags that are digits-only, or start with one, are not tags: `$1` is
        // a placeholder and must not swallow the text up to the next `$`.
        let sql = "SELECT a FROM t WHERE x = $1 AND y = $2; SELECT 2";
        let ranges = statement_ranges(sql).expect("splits");
        assert_eq!(ranges.len(), 2, "placeholders are not dollar quotes: {ranges:?}");
        assert_eq!(&sql[ranges[1].clone()], "SELECT 2");

        // Underscore-led and empty tags keep working.
        for sql in ["SELECT $_x1$;$_x1$", "SELECT $$;$$"] {
            assert_eq!(statement_ranges(sql).expect("splits").len(), 1, "{sql}");
        }

        // Still no guessing at an unterminated body.
        assert!(statement_ranges("SELECT $tag1$oops").is_none());
    }

    /// The regression the mis-lexing produced: a batch mixing a rewritten
    /// INSERT with a digit-tagged statement lost the untouched statement's
    /// source text, comments included, because `reassemble` fell back to
    /// re-rendering everything.
    #[test]
    fn a_digit_tagged_statement_keeps_its_source_text() {
        let mut rewriter = rewriter(catalog(false));
        let original =
            "INSERT INTO users (email) VALUES ('a@b.io'); SELECT $tag1$hello$tag1$ /* keep me */";
        let sql = rewritten_query(&mut rewriter, original).expect("rewritten");
        assert!(sql.contains("$tag1$hello$tag1$ /* keep me */"), "{sql}");
        assert!(!sql.contains("a@b.io"), "{sql}");
        assert_eq!(open_hex_literal(&sql, false), b"a@b.io");
    }

    /// Statement fragments chosen for their lexical hazards: every one holds a
    /// `;` (or a `$`) somewhere the scanner must *not* treat as a separator.
    fn statement_fragment() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "SELECT 1",
            "SELECT ';'",
            "SELECT ''';'''",
            "SELECT \";\" FROM t",
            "SELECT $$;$$",
            "SELECT $tag$;$tag$",
            "SELECT $tag1$;$tag1$",
            "SELECT $_9$;$_9$",
            "SELECT E'\\';'",
            "SELECT 1 /* ; */",
            "SELECT 1 /* /* ; */ */",
            "SELECT a FROM t WHERE x = $1",
            "INSERT INTO users (email) VALUES ('a;b')",
            "UPDATE users SET email = $tag2$x;y$tag2$",
        ])
        .prop_map(str::to_owned)
    }

    proptest! {
        /// `statement_ranges` is a second, hand-written SQL lexer over
        /// client-controlled text, and it is the one component whose
        /// disagreement with sqlparser `render_validated` cannot catch: when
        /// the ranges are wrong but their *count* happens to match,
        /// `reassemble` splices rendered SQL at the wrong offsets and nothing
        /// re-parses the assembled result.
        ///
        /// The invariant: whenever the ranges line up with the parsed
        /// statements, each range's text must parse to exactly the statement
        /// sqlparser found at that position.
        #[test]
        fn statement_ranges_align_with_the_parsed_statements(
            fragments in proptest::collection::vec(statement_fragment(), 1..4),
            separator in prop::sample::select(vec!["; ", ";", " ; ", ";\n", "; -- c\n"]),
        ) {
            let sql = fragments.join(separator);
            let Ok(parsed) = parse_sql(&sql) else { return Ok(()) };
            let Some(ranges) = statement_ranges(&sql) else { return Ok(()) };
            // Asserted, not assumed. `reassemble` only checks that the two
            // counts agree, so a wrong split that happens to keep the count is
            // exactly the case that reaches the server mis-spliced — assuming
            // the counts match here would skip the bugs worth finding.
            prop_assert_eq!(
                ranges.len(), parsed.len(),
                "{:?} split into {:?}",
                sql, ranges.iter().map(|r| &sql[r.clone()]).collect::<Vec<_>>()
            );

            for (range, statement) in ranges.iter().zip(&parsed) {
                let text = &sql[range.clone()];
                let reparsed = parse_sql(text).map_err(|e| {
                    TestCaseError::fail(format!("range {text:?} does not parse: {e}"))
                })?;
                prop_assert_eq!(
                    reparsed.len(), 1,
                    "range {:?} holds {} statements, not one", text, reparsed.len()
                );
                prop_assert_eq!(
                    &reparsed[0], statement,
                    "range {:?} is not the statement at its position", text
                );
            }
        }
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
            FrameAction::Reply(_) | FrameAction::RefuseAndClose(_) => {
                panic!("refused: {sql}")
            }
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
                FrameAction::Reply(_) | FrameAction::RefuseAndClose(_) => {
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

    /// One Bind can carry more than one array that cannot be indexed, and the
    /// operator has to be told about all of them: naming only the last one
    /// sends them to fix one site and meet the other on the next run.
    #[test]
    fn every_un_indexable_array_of_a_bind_is_named_not_only_the_last() {
        let catalog = Arc::new(WriteCatalog::new(
            &[column("email", transform(true), true), column("phone", transform(true), true)],
            OnUnprotected::Reject,
        ));
        let mut strict = rewriter(catalog);
        rewritten_parse(
            &mut strict,
            b"two",
            "SELECT id FROM users WHERE email = ANY($1) OR phone = ANY($2)",
        )
        .expect("rewritten");
        // int4 elements: nothing this proxy ever sealed, so both fall back.
        let ints = binary_array(23, &[Some(&1i32.to_be_bytes())]);
        let bind = bind_frame(b"two", &[1, 1], &[Some(&ints), Some(&ints)]);
        let FrameAction::Reply(frames) = strict.on_frame(b'B', &bind).unwrap() else {
            panic!("strict mode must refuse a Bind it cannot index")
        };
        let message = String::from_utf8_lossy(&frames);
        assert!(message.contains("email") && message.contains("phone"), "{message}");
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
        // A backslash escapes the next character in a *bare* element too, so
        // `{a\,b}` is one element and not two. Splitting on the raw comma would
        // index two values nobody stored and quietly return the wrong rows.
        assert_eq!(
            elements(decode_text_array(br"{a\,b}", WireForm::Text).unwrap()),
            [Some(b"a,b".to_vec())]
        );
        // Escaping also decides what is NULL and what is the string "NULL",
        // and keeps whitespace a bare element would otherwise have trimmed.
        assert_eq!(
            elements(decode_text_array(br"{\NULL,NULL,a\ }", WireForm::Text).unwrap()),
            [Some(b"NULL".to_vec()), None, Some(b"a ".to_vec())]
        );
        // A BYTEA-form column reads `\x` as hex input, the same as a literal —
        // which on the wire needs the backslash escaped, exactly as PostgreSQL
        // writes it back out. One backslash escapes the `x` instead, leaving a
        // bare `x616263` that is not hex input at all.
        assert_eq!(
            elements(decode_text_array(br"{\\x616263}", WireForm::Bytea).unwrap()),
            [Some(b"abc".to_vec())]
        );
        assert_eq!(
            elements(decode_text_array(br"{\x616263}", WireForm::Bytea).unwrap()),
            [Some(b"x616263".to_vec())]
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

    /// Element bytes drawn from the array format's own metacharacters — the
    /// quote, the escape, the braces, the separator, the NULL spelling — so a
    /// generated array actually reaches the branches that decide where one
    /// element ends and the next begins. Uniformly random bytes would spend
    /// almost every case being rejected by the first field.
    fn array_element() -> impl Strategy<Value = Option<Vec<u8>>> {
        let byte = prop::sample::select(vec![
            b'a', b'N', b'U', b'L', b'x', b',', b'"', b'\\', b'{', b'}', b' ', 0x00, 0xff,
        ]);
        prop::option::of(prop::collection::vec(byte, 0..6))
    }

    /// Wire bytes for a `= ANY($n)` parameter: arbitrary noise, both encoders'
    /// own output, and text literals assembled straight out of the format's
    /// metacharacters — the shapes no encoder produces but a client can send.
    fn array_bytes() -> impl Strategy<Value = Vec<u8>> {
        let metacharacters = prop::sample::select(vec![
            "a", ",", "\"", "\\", "{", "}", " ", "NULL", "\\x61", "\\\\x61",
        ]);
        prop_oneof![
            prop::collection::vec(any::<u8>(), 0..64),
            prop::collection::vec(array_element(), 0..6)
                .prop_map(|elements| encode_binary_array(&elements, 1).expect("encodes")),
            prop::collection::vec(array_element(), 0..6)
                .prop_map(|elements| encode_text_array(&elements)),
            prop::collection::vec(metacharacters, 0..8).prop_map(|parts| format!(
                "{{{}}}",
                parts.concat()
            )
            .into_bytes()),
        ]
    }

    proptest! {
        /// Re-encoding what was decoded is the whole codec's contract: a
        /// `= ANY($n)` array goes out as the same array with blind indexes in
        /// it, so every element the decoder produced has to survive the
        /// encoder unchanged, NULLs and element boundaries included.
        #[test]
        fn the_array_codec_round_trips_every_element(
            elements in prop::collection::vec(array_element(), 0..8),
        ) {
            let binary = encode_binary_array(&elements, 1).expect("encodes");
            let decoded = decode_binary_array(&binary).expect("decodes its own output");
            prop_assert_eq!(&decoded.elements, &elements);

            // The text encoder writes bytea `\x` hex, which is how the text
            // decoder reads a BYTEA-form column back — whatever bytes it holds.
            let text = encode_text_array(&elements);
            let decoded =
                decode_text_array(&text, WireForm::Bytea).expect("decodes its own output");
            prop_assert_eq!(&decoded.elements, &elements);
        }

        /// Both decoders read bytes a client chose, in a session task that
        /// owns the connection: a panic here is that client crashing its own
        /// session, and an index or slice off the end of a truncated array is
        /// the easiest way to write one.
        #[test]
        fn the_array_decoders_never_panic_on_arbitrary_bytes(raw in array_bytes()) {
            let _ = decode_binary_array(&raw);
            let _ = decode_text_array(&raw, WireForm::Text);
            let _ = decode_text_array(&raw, WireForm::Bytea);
        }

        /// The same, on inputs that started out well-formed. Corrupting one
        /// byte of a real encoding is what reaches the states past the header
        /// — a length field that now overruns, a quote that never closes.
        #[test]
        fn a_corrupted_array_is_rejected_but_never_panics(
            elements in prop::collection::vec(array_element(), 0..6),
            at in any::<prop::sample::Index>(),
            patch in any::<u8>(),
        ) {
            let mut binary = encode_binary_array(&elements, 1).expect("encodes");
            let index = at.index(binary.len());
            binary[index] = patch;
            let _ = decode_binary_array(&binary);

            let mut text = encode_text_array(&elements);
            let index = at.index(text.len());
            text[index] = patch;
            let _ = decode_text_array(&text, WireForm::Bytea);
        }

        /// The fail-closed contract [`index_array`] exists to keep: either the
        /// parameter is refused whole — `None`, which the caller turns into
        /// the same `on_unprotected` signal the SQL rewrite raises — or every
        /// element is the blind index of the element that was there, with the
        /// NULLs still in their places. A half-indexed array is not a broken
        /// message the backend rejects; it is a *valid* query that silently
        /// returns the wrong rows.
        #[test]
        fn an_indexed_array_is_all_or_nothing(raw in array_bytes(), binary in any::<bool>()) {
            use crate::rows::tests::INDEX_KEY;

            let transform = transform(true);
            let decoded = if binary {
                decode_binary_array(&raw)
            } else {
                decode_text_array(&raw, transform.wire())
            };
            let indexed = index_array(&raw, binary, &transform).expect("indexing cannot fail");

            let Some(array) = decoded else {
                prop_assert!(indexed.is_none(), "an undecodable array must not be indexed");
                return Ok(());
            };
            let indexed = indexed.expect("a decodable array is indexed");
            let reread = if binary {
                decode_binary_array(&indexed)
            } else {
                decode_text_array(&indexed, WireForm::Bytea)
            }
            .expect("the indexed array is itself a well-formed array");

            prop_assert_eq!(reread.elements.len(), array.elements.len(), "element count moved");
            for (before, after) in array.elements.iter().zip(&reread.elements) {
                match (before, after) {
                    (None, None) => {}
                    (Some(plaintext), Some(token)) => prop_assert_eq!(
                        token,
                        &blind_index::compute(&INDEX_KEY, plaintext).to_vec(),
                        "an element is not its own blind index"
                    ),
                    _ => prop_assert!(false, "a NULL element changed places"),
                }
            }
        }
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

    /// `UPDATE ... FROM` and `DELETE ... USING` join a second relation into
    /// the predicate's scope, and sqlparser keeps it in a field of its own. It
    /// used to be dropped, so a searchable column of the joined relation
    /// resolved to nothing: the comparison went upstream verbatim, matched no
    /// row, and never reached the gate. `DELETE FROM sessions USING users
    /// WHERE users.email = $1` silently revoked nothing — and its `<>`
    /// inversion deleted every session there was.
    #[test]
    fn the_joined_relation_of_update_from_and_delete_using_is_in_scope() {
        for sql in [
            "DELETE FROM sessions USING users \
             WHERE users.email = 'a@b.io' AND sessions.user_id = users.id",
            "UPDATE sessions SET valid = false FROM users \
             WHERE users.email = 'a@b.io' AND sessions.user_id = users.id",
        ] {
            let mut permissive = rewriter(catalog(true));
            let rewritten =
                rewritten_query(&mut permissive, sql).unwrap_or_else(|| panic!("{sql}"));
            assert!(!rewritten.contains("a@b.io"), "{rewritten}");
            assert!(rewritten.contains("FROM 1 FOR 32"), "{rewritten}");
        }

        // A derived table beside the target is a query of its own, and it was
        // walked for `SELECT` but not for these two: the equality inside it
        // went upstream as plaintext, matching nothing and signalling nothing.
        for sql in [
            "DELETE FROM sessions USING (SELECT id FROM users WHERE email = 'a@b.io') s \
             WHERE s.id = sessions.user_id",
            "UPDATE sessions SET valid = false \
             FROM (SELECT id FROM users WHERE email = 'a@b.io') s WHERE s.id = sessions.user_id",
        ] {
            let mut permissive = rewriter(catalog(true));
            let rewritten =
                rewritten_query(&mut permissive, sql).unwrap_or_else(|| panic!("{sql}"));
            assert!(!rewritten.contains("a@b.io"), "{rewritten}");
            assert!(rewritten.contains("FROM 1 FOR 32"), "{rewritten}");
        }

        // A join constraint inside that FROM/USING resolves against the same
        // scope the WHERE does, so it is the same rewrite site — and only
        // `rewrite_select` used to walk one, so these two left it comparing
        // plaintext against the stored form.
        for sql in [
            "DELETE FROM sessions USING accounts JOIN users ON users.email = 'a@b.io'",
            "UPDATE sessions SET valid = false FROM accounts JOIN users \
             ON users.email = 'a@b.io'",
        ] {
            let mut permissive = rewriter(catalog(true));
            let rewritten =
                rewritten_query(&mut permissive, sql).unwrap_or_else(|| panic!("{sql}"));
            assert!(!rewritten.contains("a@b.io"), "{rewritten}");
            assert!(rewritten.contains("FROM 1 FOR 32"), "{rewritten}");
        }

        // The inversion is the dangerous half and no index can answer it, so
        // it has to reach the gate rather than delete the table.
        for sql in [
            "DELETE FROM sessions USING users WHERE users.email <> 'a@b.io'",
            "UPDATE sessions SET valid = false FROM users WHERE users.email LIKE 'a%'",
            "DELETE FROM sessions USING accounts JOIN users ON users.email LIKE 'a%'",
        ] {
            let mut strict = rewriter(strict_catalog(true));
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(refusal(&action).contains("searchable column email"), "{sql}");
        }
    }

    /// An unqualified name that two protected relations in scope both carry
    /// cannot be rewritten — picking one would compare against the wrong
    /// table's blind index. It used to resolve to nothing at all, which put it
    /// on the same path as SQL that mentions no protected column: relayed
    /// verbatim, matching no row, and never refused under `reject`. It is a
    /// site of its own now.
    #[test]
    fn an_ambiguous_unqualified_searchable_column_is_a_signalled_site() {
        for sql in [
            "SELECT * FROM users u JOIN accounts a ON u.id = a.uid WHERE email = 'a@b.io'",
            "SELECT * FROM users u JOIN accounts a ON u.id = a.uid WHERE email IN ('a@b.io')",
            "SELECT * FROM users u JOIN accounts a ON u.id = a.uid WHERE email LIKE 'a%'",
        ] {
            let mut permissive = rewriter(ambiguous_catalog(OnUnprotected::Warn));
            assert!(rewritten_query(&mut permissive, sql).is_none(), "ambiguity must not guess");

            let mut strict = rewriter(ambiguous_catalog(OnUnprotected::Reject));
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            let message = refusal(&action);
            assert!(message.contains("email") && message.contains("qualify it"), "{message}");
        }

        // Qualifying the name resolves it, and the rewrite goes ahead.
        let mut permissive = rewriter(ambiguous_catalog(OnUnprotected::Warn));
        let sql = rewritten_query(
            &mut permissive,
            "SELECT * FROM users u JOIN accounts a ON u.id = a.uid WHERE u.email = 'a@b.io'",
        )
        .expect("rewritten");
        assert!(!sql.contains("a@b.io") && sql.contains("FROM 1 FOR 32"), "{sql}");
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

    /// A predicate over a protected column with no equality index compares the
    /// client's plaintext against a stored form that is not the plaintext, so
    /// it matches nothing. That is the failure `Unprotected` exists to report,
    /// and it must fire for every non-searchable transform kind — an operator
    /// who sets `reject` to be told about queries that cannot work gets
    /// nothing otherwise, and "no rows" reads as "no such user".
    #[test]
    fn predicates_over_protected_columns_without_an_index_are_signalled() {
        let kinds: [(&str, Arc<dyn FieldTransform>); 3] = [
            ("encrypt (searchable = false)", transform(false)),
            ("fpe", fpe_transform()),
            ("token", token_transform()),
        ];
        for (kind, column_transform) in kinds {
            for sql in [
                "SELECT id FROM users WHERE email = 'a@b.io'",
                "SELECT id FROM users WHERE 'a@b.io' = email",
                "SELECT id FROM users WHERE email IN ('a@b.io', 'c@d.io')",
                "SELECT id FROM users WHERE email LIKE 'a%'",
                "DELETE FROM users WHERE email = 'a@b.io'",
            ] {
                let mut permissive =
                    rewriter(catalog_of(column_transform.clone(), false, OnUnprotected::Warn));
                assert!(
                    rewritten_query(&mut permissive, sql).is_none(),
                    "{kind} under warn relays: {sql}"
                );

                let mut strict =
                    rewriter(catalog_of(column_transform.clone(), false, OnUnprotected::Reject));
                let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
                let message = refusal(&action);
                assert!(
                    message.contains("protected column email") && message.contains("no equality"),
                    "{kind} under reject refuses: {sql}\ngot: {message}"
                );
            }
        }
    }

    /// The remedy differs by column, so the two predicate signals stay
    /// distinct: a searchable column names its blind index, an unindexed one
    /// names the setting that would fix it.
    #[test]
    fn the_two_predicate_signals_name_different_remedies() {
        let sql = "SELECT id FROM users WHERE email LIKE 'a%'";

        let mut searchable = rewriter(strict_catalog(true));
        let message = refusal(&searchable.on_frame(b'Q', &query_frame(sql)).unwrap());
        assert!(message.contains("searchable column email"), "{message}");
        assert!(message.contains("blind index"), "{message}");

        let mut unindexed = rewriter(strict_catalog(false));
        let message = refusal(&unindexed.on_frame(b'Q', &query_frame(sql)).unwrap());
        assert!(message.contains("protected column email"), "{message}");
        assert!(message.contains("searchable = true"), "{message}");
    }

    /// A mask-only column stores the plaintext, so its predicates are correct
    /// exactly as written and must stay silent. `WriteCatalog::new` skips
    /// columns with no transform, which is what makes this hold.
    #[test]
    fn predicates_over_mask_only_columns_stay_quiet() {
        let mask_only = ProtectedColumn {
            schema: "public".into(),
            table: "users".into(),
            column: "email".into(),
            transform: None,
            searchable: false,
            readable: false,
            mask: Some(dbsec_core::mask::MaskSpec { keep_first: 1, keep_last: 0, mask_with: '*' }),
        };
        let catalog = Arc::new(WriteCatalog::new(&[mask_only], OnUnprotected::Reject));
        let mut strict = rewriter(catalog);
        for sql in [
            "SELECT id FROM users WHERE email = 'a@b.io'",
            "SELECT id FROM users WHERE email LIKE 'a%'",
            "SELECT id FROM users WHERE email IN ('a@b.io')",
        ] {
            assert!(
                matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
                "a mask-only column stores the plaintext: {sql}"
            );
        }
    }

    /// Nullness survives sealing, so the two null tests are answered correctly
    /// by the stored form and must not be reported as unprotected. Both modes
    /// are checked through the same `unprotected` call site: silence under
    /// `reject` is what proves there is no warning under `warn`.
    #[test]
    fn null_tests_over_searchable_columns_are_not_unprotected_sites() {
        for sql in [
            "SELECT id FROM users WHERE email IS NULL",
            "SELECT id FROM users WHERE email IS NOT NULL",
            "SELECT id FROM users WHERE id > 4 AND email IS NOT NULL",
            "SELECT u.id FROM users u JOIN other o ON o.id = u.id AND u.email IS NULL",
        ] {
            let mut permissive = rewriter(catalog(true));
            assert!(rewritten_query(&mut permissive, sql).is_none(), "{sql}");

            let mut strict = rewriter(strict_catalog(true));
            assert!(
                matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
                "a null test matches correctly against the stored form: {sql}"
            );
        }
    }

    /// `IS DISTINCT FROM` is not in the same position as `IS NULL`: it
    /// compares against the stored form like any other operator, so it stays a
    /// signalled site.
    #[test]
    fn is_distinct_from_over_a_searchable_column_is_still_signalled() {
        for sql in [
            "SELECT id FROM users WHERE email IS DISTINCT FROM 'a@b.io'",
            "SELECT id FROM users WHERE email IS NOT DISTINCT FROM 'a@b.io'",
        ] {
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
        let SelectItem::UnnamedExpr(expr) = &select.projection[0] else { panic!("an expression") };
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

        let _capture = crate::log_capture();
        let captured = CapturedEvents::default();
        let subscriber = tracing_subscriber::registry().with(captured.clone());
        tracing::subscriber::with_default(subscriber, || {
            // The ambiguity site needs two protected relations in scope, so it
            // is driven through a catalog of its own.
            let mut ambiguous = rewriter(ambiguous_catalog(OnUnprotected::Warn));
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
                "SET SCHEMA 'tenant7'",
                "SELECT set_config('search_path', 'tenant7', false)",
                "SET standard_conforming_strings = off",
                "INSERT INTO users (email) VALUES ('hank@secret.test')",
                // The non-`'...'` literal syntaxes. These now seal rather than
                // pass through, but they must not reach the log on the way —
                // and wrapping one in a function call puts it back on a
                // passthrough site, where the value is logged if anything is.
                r"INSERT INTO users (email) VALUES (lower(E'ivan\'s@secret.test'))",
                "INSERT INTO users (email) VALUES (lower($$judy@secret.test$$))",
                r"UPDATE users SET email = E'kate\'s@secret.test'",
                r"SELECT id FROM users WHERE email LIKE E'liam\'s@secret.test%'",
            ] {
                // Errors are the point of some of these; only the log matters.
                drop(rewriter.on_frame(b'Q', &query_frame(sql)));
            }
            drop(ambiguous.on_frame(
                b'Q',
                &query_frame(
                    "SELECT * FROM users u JOIN accounts a ON u.id = a.uid \
                     WHERE email = 'mona@secret.test'",
                ),
            ));
        });

        let events = captured.0.lock().unwrap().join("\n");
        assert!(events.contains("passing through unencrypted"), "the sites did emit: {events}");
        for plaintext in [
            "alice", "bob", "carol", "dave", "erin", "fred", "gina", "hank", "ivan", "judy",
            "kate", "liam", "mona", "secret",
        ] {
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
