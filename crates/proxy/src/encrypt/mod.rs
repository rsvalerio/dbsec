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
//! as `bytea[]` at Bind time ([`index_array`](array::index_array)). They are rewritten wherever
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
//! on correct queries stops being read. See [`protected_operand`](scope::protected_operand).
//!
//! # SQL text fidelity
//!
//! sqlparser's `Display` is not a guaranteed round-trip of its input:
//! comments, whitespace, quoting style and dollar-quoted bodies are all
//! normalized away. So only statements the rewrite actually changed are
//! re-rendered; every other statement in a multi-statement `Query`, and all
//! text between statements, is relayed exactly as the client wrote it. What is
//! re-rendered is re-parsed and compared against the AST it came from before
//! it goes on the wire ([`render_validated`](lexer::render_validated)) — a
//! divergence fails the session instead of executing SQL the client did not
//! write.
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
//! | `shape` | an AST discriminant such as `"function call"` ([`expr_shape`](scope::expr_shape)) |
//! | `error_kind` | the sqlparser error *variant* ([`parser_error_kind`](unprotected::parser_error_kind)) — never its message, which embeds the offending token |
//! | `statements` | a count |
//!
//! Anything added later must stay inside that set;
//! `no_event_from_the_write_path_carries_a_plaintext_value` is the test that
//! keeps it honest by driving every site and grepping the emitted events. It
//! stays every site because the test ends in an exhaustive match over a value
//! of each `Unprotected` variant: a variant added without a driver does not
//! compile, and one whose driver stops firing fails the assertion.
//!
//! # Module layout
//!
//! What stays in this file is the state and the vocabulary the rest share:
//! [`QueryRewriter`] itself, the catalog lookups every layer starts from, the
//! [`Unprotected`] decision point, and the small types a value's sealing is
//! described with. Everything that *does* something lives in a module named
//! after the question it answers, so a reviewer can hold one at a time:
//!
//! | Module | What it decides |
//! |---|---|
//! | `frame` | which pgwire frames carry SQL or values, and what a refusal looks like on the wire |
//! | `lexer` | how one SQL text is tokenized, parsed, split into statements and put back together |
//! | `statement` | what each statement kind does about protected columns |
//! | `query` | what a query puts in scope, and every place inside it a predicate can hide |
//! | `predicate` | which comparisons are about a protected column, and which of those have a searchable rewrite |
//! | `seal` | which row a write binds to, and the single point where a plaintext becomes a stored form |
//! | `scope` | resolving a column reference against the relations in scope |
//! | `catalog` | which tables and columns are protected, and how a SQL name resolves to one |
//! | `settings` | which session settings a statement moves, read from tokens |
//! | `array` | the Bind-time `bytea[]` codec behind `= ANY($n)` |
//! | `unprotected` | the site descriptions themselves, and how each renders as a warning or a refusal
//!
//! Each of those carries its own unit tests. Two test-only modules sit beside
//! them: `test_support` holds the fixtures they all share, and `tests_e2e`
//! holds the suite that drives whole frames and so belongs to no single layer. |

mod lexer;

mod array;

mod settings;
pub(crate) use settings::is_on_value;

mod unprotected;
pub(crate) use unprotected::error_response;

mod catalog;
pub use catalog::WriteCatalog;

mod frame;
mod predicate;
mod query;
mod scope;
mod seal;
mod statement;

#[cfg(test)]
pub(in crate::encrypt) mod test_support;
#[cfg(test)]
mod tests_e2e;
use scope::{column_ref, TableScope};

use catalog::{normalize, Columns};

use unprotected::Unprotected;

use settings::SettingMoved;

use std::collections::HashSet;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;

use dbsec_core::transform::{FieldTransform, WireForm};
use sqlparser::ast::{Expr, ObjectName, Value};

use crate::config::OnUnprotected;
use crate::portal::{ParamTransforms, RowKeySource, SessionPortals};
use crate::rows::RowContext;
use crate::Error;

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
    /// statement is unrewritable under any setting ([`record_param`](frame::record_param)).
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

/// One cell a value is being sealed into: which transform, which column, and —
/// when the table declares a row key — which row.
///
/// A struct rather than three parameters because the repo caps a function at
/// five, and because the three travel together everywhere: a caller that had
/// the transform but forgot the row would seal a row-bound column with
/// cell-only binding, which is exactly the silent under-protection this
/// feature exists to remove.
struct SealTarget<'a> {
    transform: &'a Arc<dyn FieldTransform>,
    column: &'a str,
    row: &'a RowKeySource,
}

/// Which row an assignment list writes, so its protected values can be sealed
/// against it.
///
/// The "cannot say" cases are carried rather than acted on where they are
/// discovered, because whether they matter depends on what the list turns out
/// to assign: `ON CONFLICT (email) DO UPDATE SET hits = hits + 1` names no row
/// and needs none, and reporting it as an unprotected site would refuse
/// correct SQL under `reject`. [`QueryRewriter::row_of`] resolves this at the
/// one point where it is known that a protected value is about to be sealed,
/// and under `warn` falls back to cell-only binding — the protection this
/// table had before it declared a row key, never plaintext.
enum AssignmentRow {
    /// The row is known — or the table declares no row key at all, in which
    /// case this holds [`RowKeySource::None`] and binding is cell-only, as it
    /// was before row keys existed.
    Known(RowKeySource),
    /// The table is row-bound and the statement does not pin the row this list
    /// writes, so there is no key to seal against.
    Missing { table: String, column: String, shape: &'static str },
    /// The list assigns the row key column itself. The key the statement pins
    /// is the row the values are being moved *out of*, so sealing against it
    /// stores bytes that can never be opened again.
    Reassigned { table: String, column: String },
}

/// What an assignment list may write into: the target table's protected
/// columns, and what the rest of the same statement already sealed.
struct AssignmentScope<'a> {
    /// Which row this assignment list writes, when the target table declares a
    /// row key. [`AssignmentRow::Known`] with [`RowKeySource::None`] is the
    /// ordinary cell-only case.
    row: AssignmentRow,
    columns: &'a Columns,
    sealed: SealedValues,
}

impl AssignmentScope<'_> {
    /// A plain `UPDATE`: no `EXCLUDED` relation exists, so no value in this
    /// statement is one the proxy sealed a clause earlier.
    fn of(columns: &Columns, row: AssignmentRow) -> AssignmentScope<'_> {
        AssignmentScope { row, columns, sealed: SealedValues::default() }
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
    ///
    /// One more condition is checked by the caller rather than here, because
    /// it is not a property of the expression: on a row-bound table the sealed
    /// value carries the *inserted* row's key, so re-storing it into the
    /// conflicting row is only correct when the two are the same row.
    /// [`QueryRewriter::seal_assignments`] therefore resolves the conflict
    /// action's row before consulting this whitelist, so a conflict target
    /// that does not prove the two rows share a key is reported — refused
    /// under `reject` — rather than waved through as "already sealed".
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
    /// The live read-path resolution, consulted only for declared row keys.
    ///
    /// The write path matches by name and the read path by OID, and a row key
    /// needs both: the name to find it in the statement, the catalog type to
    /// canonicalise its value. Taking the shared context rather than a startup
    /// snapshot means a migration that changes the key column is picked up by
    /// the same refresh that fixes the columns — the drift this proxy already
    /// has machinery for.
    rows: Option<Arc<RowContext>>,
    /// Whether unqualified table names still resolve to `public`.
    search_path_trusted: bool,
    /// Whether the session turned `standard_conforming_strings` off. With it
    /// off, PostgreSQL reads a backslash in an ordinary `'…'` literal as the
    /// start of an escape and sqlparser does not, so the two no longer agree
    /// on what such a literal contains.
    escape_strings: bool,
    /// What the startup packet moved before the session's first statement, not
    /// yet reported. Held rather than reported at construction because a
    /// refusal has to answer a frame, and at connect time there is none: the
    /// move is reported on the first statement instead, which is the first
    /// moment the proxy reads a literal it and the server may disagree about.
    startup_moved: Vec<SettingMoved>,
    /// Set after refusing an extended-protocol message: the backend never saw
    /// it, so the proxy plays the backend's part and discards the rest of the
    /// batch up to `Sync`.
    awaiting_sync: bool,
}

/// What the startup packet already told the proxy about the session, before any
/// statement has been seen.
///
/// Both settings can be moved at connect time — as a startup parameter, or
/// through `options=-c <name>=<value>` — as well as mid-session, and the two
/// halves have to agree: a client that turns a setting off in its
/// StartupMessage is in exactly the state a `SET` would have put it in, and the
/// rewrite must not assume otherwise from the first statement onwards.
#[derive(Debug, Clone, Copy)]
pub struct StartupSettings {
    /// Whether unqualified table names still resolve to `public`.
    pub search_path_trusted: bool,
    /// Whether `standard_conforming_strings` is off, so PostgreSQL reads a
    /// backslash in an ordinary `'…'` literal as the start of an escape.
    pub escape_strings: bool,
}

impl Default for StartupSettings {
    /// What a startup packet that moved nothing leaves behind: unqualified
    /// names resolve to `public`, and an ordinary literal means to the server
    /// what it means to the proxy's parser.
    fn default() -> Self {
        Self { search_path_trusted: true, escape_strings: false }
    }
}

impl QueryRewriter {
    pub fn new(
        catalog: Arc<WriteCatalog>,
        portals: Arc<SessionPortals>,
        rows: Option<Arc<RowContext>>,
        tx_status: Arc<AtomicU8>,
        startup: StartupSettings,
    ) -> Self {
        // A `search_path` moved by the startup packet is deliberately not held
        // for reporting: it is reported per unqualified name by [`Self::table`],
        // which can name the table it declined to resolve. A
        // `standard_conforming_strings` already off has no such site until a
        // backslash literal reaches one, so the session-level report is what
        // tells the operator the connection is diverging at all.
        let startup_moved =
            if startup.escape_strings { vec![SettingMoved::EscapeStrings] } else { Vec::new() };
        Self {
            catalog,
            portals,
            rows,
            tx_status,
            search_path_trusted: startup.search_path_trusted,
            escape_strings: startup.escape_strings,
            startup_moved,
            awaiting_sync: false,
        }
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
}

/// The zero-based parameter index a `$n` placeholder refers to, or `None` when
/// it names no bindable parameter.
///
/// `n` is client-supplied SQL, so the subtraction is checked: PostgreSQL
/// numbers parameters from 1 and `$0` is not a parameter at all. Subtracting
/// unchecked panicked the session task in debug builds and wrapped to
/// `usize::MAX` in release, where the rewrite went ahead against an index no
/// Bind can ever fill (SEC-15).
pub(super) fn placeholder_index(placeholder: &str) -> Option<usize> {
    placeholder.strip_prefix('$').and_then(|n| n.parse::<usize>().ok())?.checked_sub(1)
}

/// Peels the casts and parentheses drivers wrap literals in — psycopg's
/// client-side binding renders every bytes parameter as `'\x…'::bytea` — so
/// the value underneath can be recognised.
pub(super) fn unwrap_casts(expr: &Expr) -> &Expr {
    match expr {
        Expr::Cast { expr, .. } | Expr::Nested(expr) => unwrap_casts(expr),
        other => other,
    }
}

/// The plaintext a piece of text stands for — shared by SQL literals and text
/// format array elements, which read `\x` the same way.
pub(super) fn text_plaintext(text: &str, wire: WireForm) -> Vec<u8> {
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
