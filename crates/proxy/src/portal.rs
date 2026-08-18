//! Extended-protocol session state: the bookkeeping both relay directions
//! need to agree on.
//!
//! The write path (`encrypt::QueryRewriter`) sees Parse/Bind/Describe/Execute;
//! the read path (`rows::RowDecryptor`) sees RowDescription/DataRow. In the
//! *simple* protocol every result set is introduced by its own RowDescription,
//! so the read path is self-sufficient. In the extended protocol it is not:
//! the server sends RowDescription in reply to **Describe**, not to Execute,
//! so a client that describes a statement once and then binds and executes it
//! many times — which is what every prepared-statement cache does — produces
//! DataRows with no RowDescription in front of them. Keying protected column
//! positions to "the last RowDescription seen on this connection" then
//! decrypts one statement's rows with another statement's positions, or
//! relays a protected column untouched — raw ciphertext to the client, with
//! no error (CL-3).
//!
//! So the two directions share this state. The write path records what it
//! sent and which response it expects; the read path consumes those
//! expectations in order and asks which statement the rows now in flight
//! belong to. The ordering is sound without any further synchronisation: the
//! relay hands each frame to its transform *before* forwarding it, so the
//! write path's record happens-before the frame reaches the server, which
//! happens-before the response the read path is matching against.
//!
//! Recovery is anchored on ReadyForQuery. A failed Parse makes the server skip
//! every remaining message of the batch, so expectations queued behind it
//! never get a response; the Sync marker queued for each batch is what lets
//! the read path drop exactly that batch's leftovers and stay aligned with a
//! pipelined next batch.
//!
//! One class of client frame is outside that argument: PostgreSQL silently
//! discards `CopyData`/`CopyDone`/`CopyFail` received outside a copy — no
//! ErrorResponse, no ReadyForQuery, no response at all — so seeing one tells
//! the write path nothing about what the backend will do. Whether a copy is
//! really in progress is only knowable from the CopyInResponse the *read* path
//! sees, so that too is shared state here ([`SessionPortals::copy_data`]);
//! without it a client could pop this batch's markers with a stray frame and
//! desync every response behind it.
//!
//! A queued expectation therefore has to outlive the names it was made about.
//! A client may `Close` a statement or portal in the same batch that executes
//! it — the PostgreSQL JDBC driver does exactly that for a statement it has
//! decided not to cache — so by the time the rows come back the map entry is
//! gone. [`Pending::Execute`] consequently carries the [`Positions`] it will
//! be decrypted with rather than a name to look up later, and a
//! [`StatementId`] distinguishes one incarnation of a name from the next, so
//! that a `Close` orphans nothing and a re-`Parse` inherits nothing.
//!
//! Every map here is keyed by a client-chosen name, so every one of them is
//! capped — names, statements, portals and outstanding responses (SEC-33).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use dbsec_core::envelope::RowKey;
use dbsec_core::sync::Unpoisoned as _;
use dbsec_core::transform::FieldTransform;

use crate::rows::Described;
use crate::Error;

/// Prepared statements one session may hold at once. Drivers cache tens of
/// statements per connection (sqlx defaults to 100), so this is roughly an
/// order of magnitude above any real client and still bounds the map a client
/// can grow with `Parse` messages it never closes.
pub const MAX_PREPARED_STATEMENTS: usize = 1024;

/// Portals one session may hold at once. Clients that are not pipelining reuse
/// the unnamed portal, so this bounds the same abuse as the statement cap.
pub const MAX_PORTALS: usize = 1024;

/// Longest statement or portal name accepted. PostgreSQL identifiers are
/// capped at 63 bytes, so this leaves generous room while keeping a 1 GiB
/// `Parse` body from becoming a 1 GiB map key.
pub const MAX_NAME_LEN: usize = 256;

/// Responses a session may have outstanding. A client that pipelines without
/// ever sending Sync would otherwise grow this queue for the life of the
/// session; real pipelines are orders of magnitude shorter.
pub const MAX_PENDING_RESPONSES: usize = 4096;

/// The client's `CopyData` message type — the one copy frame that does *not*
/// end the copy, unlike `CopyDone` (`'c'`) and `CopyFail` (`'f'`).
const COPY_DATA: u8 = b'd';

/// What one RowDescription said about a result set. Shared behind an `Arc`
/// because the same description serves every Execute of the statement it
/// belongs to — which is also why it carries the resolution it was computed
/// against; see [`crate::rows::Described`].
pub type Positions = Arc<Described>;

/// What Bind must do to one parameter of a prepared statement.
#[derive(Clone)]
pub enum ParamAction {
    /// The parameter feeds a protected column: seal it.
    Seal { transform: Arc<dyn FieldTransform>, row: RowKeySource },
    /// The parameter is compared for equality against a searchable column:
    /// replace it with the blind index (the SQL was rewritten to match the
    /// index prefix).
    SearchIndex(Arc<dyn FieldTransform>),
    /// The parameter is the bound array of a `col = ANY($n)` over a searchable
    /// column: every element is replaced by its blind index and the array
    /// re-encoded as `bytea[]`. The column name travels with it because the
    /// fallback for an array Bind cannot decode is the same
    /// `Unprotected::Predicate` signal the SQL rewrite would have raised, and
    /// that signal names the column.
    SearchIndexArray { transform: Arc<dyn FieldTransform>, column: Arc<str> },
}

/// Where the row key for a sealed parameter comes from.
///
/// A row-bound value cannot be sealed until its row is known, and for a bound
/// parameter the row is often another bound parameter — `UPDATE users SET
/// ssn = $1 WHERE id = $2` knows nothing about `$2` until Bind. So the *source*
/// of the key crosses Parse→Bind, and the key itself is resolved at Bind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowKeySource {
    /// The column's table declares no row key: cell-only binding, as before.
    None,
    /// The row key was a literal in the statement, canonicalised at rewrite
    /// time because the statement text is all it depends on.
    Literal(RowKey),
    /// The row key is another placeholder, canonicalised at Bind from that
    /// parameter's bytes. The type is carried because those bytes cannot be
    /// interpreted without it (see `crate::rowkey`).
    Param { index: usize, type_oid: u32 },
}

impl ParamAction {
    /// Whether two actions on one parameter ask for the same wire value, and
    /// so can be satisfied by transforming it once.
    fn agrees_with(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Seal { transform: a, row: left }, Self::Seal { transform: b, row: right }) => {
                Arc::ptr_eq(a, b) && left == right
            }
            (Self::SearchIndex(a), Self::SearchIndex(b)) => Arc::ptr_eq(a, b),
            (
                Self::SearchIndexArray { transform: a, column: left },
                Self::SearchIndexArray { transform: b, column: right },
            ) => Arc::ptr_eq(a, b) && left == right,
            _ => false,
        }
    }
}

/// Which parameter placeholders of a prepared statement need transforming,
/// with **at most one action per index**.
///
/// A Bind carries one value per placeholder, so one placeholder cannot be both
/// sealed and blind-indexed, nor sealed under two different transforms: the
/// wire has room for exactly one of the two answers. Applying both in sequence
/// (the previous behaviour) sealed a value and then indexed the *ciphertext*,
/// or sealed an already-sealed value — silently, and in the second case
/// irreversibly. [`Self::record`] therefore collapses a repeat of the same
/// action and rejects a conflicting one, which refuses the statement rather
/// than writing something no read path can undo (CL-3). The refusal is
/// statement-level — see `encrypt::record_param`, which turns it into the
/// ErrorResponse the client is told about.
#[derive(Clone, Default)]
pub struct ParamTransforms {
    entries: Vec<(usize, ParamAction)>,
}

impl ParamTransforms {
    /// Records what Bind must do to parameter `index` (zero-based).
    ///
    /// Repeating the same action for the same placeholder — `INSERT INTO t
    /// (email) VALUES ($1), ($1)` walks the same column twice — is collapsed
    /// into one. Two *different* actions for one placeholder cannot both be
    /// honoured and return [`Error::ConflictingParameter`].
    pub fn record(&mut self, index: usize, action: ParamAction) -> Result<(), Error> {
        match self.entries.iter().find(|(existing, _)| *existing == index) {
            Some((_, existing)) if existing.agrees_with(&action) => Ok(()),
            Some(_) => Err(Error::ConflictingParameter { placeholder: index.saturating_add(1) }),
            None => {
                self.entries.push((index, action));
                Ok(())
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &(usize, ParamAction)> {
        self.entries.iter()
    }
}

/// What a Describe message asks about.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    Statement,
    Portal,
}

/// Where the positions for the DataRow now arriving come from.
pub enum RowSource {
    /// The rows belong to a portal whose statement the server has described.
    Portal(Positions),
    /// No Execute is outstanding, so the rows follow their own RowDescription:
    /// the simple protocol, where the last `'T'` frame *is* the authority.
    LastDescription,
    /// An Execute is outstanding for a statement the server never described.
    /// Nothing on the connection says which columns these rows carry.
    Undescribed,
}

/// Identifies one *incarnation* of a prepared statement name. `Parse` of a
/// name that already exists mints a fresh id, so a description answered for
/// the previous incarnation is never attributed to the new one — and a queued
/// Execute keeps pointing at the incarnation it was bound against even after
/// the name is closed or re-parsed.
type StatementId = u64;

/// The statement a queued Describe is about: its name, to find the map entry,
/// and its id, to confirm the entry is still the same incarnation.
struct StatementRef {
    name: Vec<u8>,
    id: StatementId,
}

/// One prepared statement, as both directions see it.
struct Statement {
    /// Which incarnation of this name it is.
    id: StatementId,
    /// Write path: what Bind must do to each parameter.
    params: ParamTransforms,
    /// Read path: the protected positions of the RowDescription that described
    /// this statement (or one of its portals). `None` until the server
    /// describes it.
    described: Option<Positions>,
}

/// A response the server still owes, in the order the client asked for it.
enum Pending {
    /// A Describe, answered by RowDescription or NoData.
    Describe(Option<StatementRef>),
    /// An Execute of a portal, answered by DataRows plus a completion frame.
    ///
    /// `positions` is what the read path will decrypt with, held *here* rather
    /// than looked up by name when the DataRow arrives. The name is not a
    /// stable handle: a client may pipeline `Close S` for a statement in the
    /// same batch that executes it — the PostgreSQL JDBC driver does exactly
    /// that for a statement it has decided not to cache — so by the time the
    /// rows come back the entry is gone and the lookup finds nothing. Resolving
    /// late turned that ordinary traffic into `Error::UndescribedRow`, which
    /// the read path answers by tearing the session down.
    ///
    /// It is filled in two moments, because either can come first: at
    /// [`SessionPortals::expect_execute`] when the statement is already
    /// described, and by [`SessionPortals::describe_answered`] back-filling
    /// this queue when the description arrives after the Execute was queued —
    /// which is the usual case, since a pipelined batch is fully on the wire
    /// before its first response comes back.
    Execute { statement: Option<StatementId>, positions: Option<Positions> },
    /// A Sync (or a simple Query), answered by ReadyForQuery. Marks the batch
    /// boundary the read path resynchronises on.
    Batch,
}

#[derive(Default)]
struct Tracked {
    statements: HashMap<Vec<u8>, Statement>,
    /// Portal name → the statement it was bound to.
    portals: HashMap<Vec<u8>, Vec<u8>>,
    pending: VecDeque<Pending>,
    /// Source of [`StatementId`]s. Monotonic for the life of the session, so
    /// an id is never reused and a stale reference can only fail to match.
    next_statement_id: StatementId,
    /// Whether the backend has answered with a CopyInResponse (or a
    /// CopyBothResponse) that no CopyDone/CopyFail or ReadyForQuery has
    /// finished yet. Only the read path can know this — the response travels
    /// upstream→client — which is why it lives here rather than in the write
    /// path that consumes it. See [`Self::copy_data`].
    copy_in: bool,
}

/// One session's extended-protocol state, shared by its two relay tasks.
///
/// Both directions only ever take this lock for a single map or queue
/// operation and never across an `.await`, so the two relays cannot block each
/// other for longer than a lookup (CONC-2).
#[derive(Default)]
pub struct SessionPortals(Mutex<Tracked>);

impl SessionPortals {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A poisoned lock means the *other* direction's task panicked. Every
    /// method here is a single map or queue operation, so what it left behind
    /// is structurally intact; refusing to read it would turn one task's bug
    /// into a second panic in a session that is being torn down anyway.
    fn tracked(&self) -> MutexGuard<'_, Tracked> {
        self.0.lock().unpoisoned()
    }

    /// Remembers a freshly parsed statement, replacing any statement of the
    /// same name — including the description the previous one carried, which
    /// no longer describes anything.
    pub fn parse(&self, statement: &[u8], params: ParamTransforms) -> Result<(), Error> {
        check_name("prepared statement", statement)?;
        let mut tracked = self.tracked();
        if !tracked.statements.contains_key(statement)
            && tracked.statements.len() >= MAX_PREPARED_STATEMENTS
        {
            return Err(Error::SessionLimit {
                what: "prepared statements",
                limit: MAX_PREPARED_STATEMENTS,
            });
        }
        let id = tracked.next_statement_id;
        tracked.next_statement_id += 1;
        tracked.statements.insert(statement.to_vec(), Statement { id, params, described: None });
        Ok(())
    }

    /// Binds a portal to a statement and returns what Bind must do to the
    /// parameters, or `None` for a statement this session never parsed (the
    /// server will reject the Bind itself).
    pub fn bind(&self, portal: &[u8], statement: &[u8]) -> Result<Option<ParamTransforms>, Error> {
        check_name("portal", portal)?;
        check_name("prepared statement", statement)?;
        let mut tracked = self.tracked();
        if !tracked.portals.contains_key(portal) && tracked.portals.len() >= MAX_PORTALS {
            return Err(Error::SessionLimit { what: "portals", limit: MAX_PORTALS });
        }
        tracked.portals.insert(portal.to_vec(), statement.to_vec());
        Ok(tracked.statements.get(statement).map(|statement| statement.params.clone()))
    }

    /// Closing a statement also closes every portal built from it, exactly as
    /// the server does.
    pub fn close_statement(&self, statement: &[u8]) {
        let mut tracked = self.tracked();
        tracked.statements.remove(statement);
        tracked.portals.retain(|_, bound| bound != statement);
    }

    pub fn close_portal(&self, portal: &[u8]) {
        self.tracked().portals.remove(portal);
    }

    /// Records that the server owes a RowDescription (or NoData) for `name`.
    pub fn expect_describe(&self, target: Target, name: &[u8]) -> Result<(), Error> {
        check_name("describe target", name)?;
        let mut tracked = self.tracked();
        let name = match target {
            Target::Statement => Some(name.to_vec()),
            // A portal describes the statement it was bound to: every portal
            // of one statement returns the same columns.
            Target::Portal => tracked.portals.get(name).cloned(),
        };
        let statement = name.and_then(|name| {
            let id = tracked.statements.get(&name)?.id;
            Some(StatementRef { name, id })
        });
        push(&mut tracked, Pending::Describe(statement))
    }

    /// Records that the server owes the DataRows of `portal`.
    ///
    /// The statement's positions are captured here when it is already
    /// described; otherwise [`Self::describe_answered`] fills them in when the
    /// RowDescription arrives. Either way they are held in the queue entry, so
    /// closing or re-parsing the statement in the meantime cannot orphan the
    /// rows already in flight for it.
    pub fn expect_execute(&self, portal: &[u8]) -> Result<(), Error> {
        let mut tracked = self.tracked();
        let statement = tracked
            .portals
            .get(portal)
            .and_then(|name| tracked.statements.get(name))
            .map(|statement| (statement.id, statement.described.clone()));
        let (statement, positions) = match statement {
            Some((id, described)) => (Some(id), described),
            None => (None, None),
        };
        push(&mut tracked, Pending::Execute { statement, positions })
    }

    /// The backend answered with CopyInResponse or CopyBothResponse: from here
    /// until the copy ends, the client's `CopyData`/`CopyDone`/`CopyFail`
    /// frames are the payload of a copy actually in progress.
    ///
    /// Observed by the *read* path, because that is the direction the response
    /// travels in. The write path cannot tell a payload frame from a stray one
    /// on its own — see [`Self::copy_data`].
    pub fn copy_in_started(&self) {
        self.tracked().copy_in = true;
    }

    /// The client sent `CopyData`, `CopyDone` or `CopyFail` (`msg_type` is
    /// `'d'`, `'c'` or `'f'`).
    ///
    /// **While a copy is really in progress**, the backend **ignores Flush and
    /// Sync**. The Sync that would normally close the batch was already on the
    /// wire before the CopyInResponse came back (drivers pipeline
    /// Bind/Execute/Sync and only then look at the answer), so a batch marker
    /// is sitting in the queue for a ReadyForQuery the backend will never
    /// send. Left there it absorbs the *next* batch's ReadyForQuery, and from
    /// then on every expectation is one response behind — which surfaces as a
    /// DataRow the read path cannot attribute to any portal.
    ///
    /// Only markers queued after the Execute that started the copy are
    /// dropped. A simple-protocol `COPY ... FROM STDIN` has no Execute and its
    /// ReadyForQuery is not skipped, so its marker stays.
    ///
    /// **Outside copy mode nothing here moves.** PostgreSQL discards `d`/`c`/
    /// `f` received outside a copy silently — no ErrorResponse, no
    /// ReadyForQuery, no response of any kind — so a stray copy frame owes
    /// nothing and settles nothing. Acting on it anyway let a client pop this
    /// batch's `Batch` marker at will and desync the queue against a backend
    /// that had done nothing: every later response is then matched to the
    /// expectation in front of the one it answers, which fails closed as
    /// `Error::UndescribedRow` or a crypto error, i.e. a client-driven forced
    /// refusal of its own session (SEC-33).
    pub fn copy_data(&self, msg_type: u8) {
        let mut tracked = self.tracked();
        if !tracked.copy_in {
            return;
        }
        // CopyDone/CopyFail end the copy: the backend leaves copy-in mode and
        // answers the Execute, so it is no longer skipping anything.
        if msg_type != COPY_DATA {
            tracked.copy_in = false;
        }
        let Some(execute) =
            tracked.pending.iter().rposition(|p| matches!(p, Pending::Execute { .. }))
        else {
            return;
        };
        while tracked.pending.len() > execute + 1
            && matches!(tracked.pending.back(), Some(Pending::Batch))
        {
            tracked.pending.pop_back();
        }
    }

    /// Records a batch boundary: the server owes a ReadyForQuery.
    pub fn expect_batch(&self) -> Result<(), Error> {
        let mut tracked = self.tracked();
        push(&mut tracked, Pending::Batch)
    }

    /// Attributes a RowDescription to the Describe that asked for it, so every
    /// Execute of that statement knows its protected positions — the ones
    /// still queued behind this Describe as well as any bound later.
    ///
    /// The back-fill is what makes a pipelined batch work at all: the client
    /// sends Describe and Execute together and only then reads, so by the time
    /// this description arrives its Execute is already queued with no
    /// positions. Matching on [`StatementId`] rather than name means a
    /// `Close` or a re-`Parse` of the name in between changes nothing — a
    /// closed statement's queued Execute still gets the description that was
    /// asked for it, and a re-parsed name's Execute (a different id) is
    /// correctly left alone.
    pub fn describe_answered(&self, positions: &Positions) {
        let mut tracked = self.tracked();
        let Some(Pending::Describe(statement)) = tracked.pending.front() else { return };
        let statement = statement.as_ref().map(|it| (it.name.clone(), it.id));
        tracked.pending.pop_front();
        let Some((name, id)) = statement else { return };

        // The name may since have been closed or re-parsed; only the same
        // incarnation is still described by this answer.
        if let Some(entry) = tracked.statements.get_mut(&name) {
            if entry.id == id {
                entry.described = Some(positions.clone());
            }
        }
        for pending in &mut tracked.pending {
            if let Pending::Execute { statement: Some(queued), positions: slot } = pending {
                if *queued == id && slot.is_none() {
                    *slot = Some(positions.clone());
                }
            }
        }
    }

    /// A Describe answered with NoData: the statement returns no rows at all,
    /// which is still a description — an Execute of it must not fall back to
    /// some other statement's positions.
    pub fn no_data(&self) {
        self.describe_answered(&Positions::default());
    }

    /// Replaces the description of the Execute now being answered with one
    /// re-derived against a newer resolution, so the rest of that result set
    /// costs nothing more than the comparison. Only the front entry: the
    /// re-derivation is of *this* result set's fields, and the Executes queued
    /// behind it describe other statements.
    ///
    /// See [`crate::rows::RowDecryptor::current`].
    pub fn rederived(&self, positions: &Positions) {
        let mut tracked = self.tracked();
        if let Some(Pending::Execute { positions: slot @ Some(_), .. }) =
            tracked.pending.front_mut()
        {
            *slot = Some(positions.clone());
        }
    }

    /// Which positions the DataRow now arriving must be decrypted with.
    ///
    /// Read straight out of the queue entry: no map lookup, so a statement
    /// closed or re-parsed since the Execute was queued cannot leave the rows
    /// in flight for it unattributable.
    pub fn row_source(&self) -> RowSource {
        let tracked = self.tracked();
        let Some(Pending::Execute { positions, .. }) = tracked.pending.front() else {
            return RowSource::LastDescription;
        };
        positions.clone().map_or(RowSource::Undescribed, RowSource::Portal)
    }

    /// A result set ended: CommandComplete, PortalSuspended or
    /// EmptyQueryResponse.
    pub fn execute_answered(&self) {
        let mut tracked = self.tracked();
        if matches!(tracked.pending.front(), Some(Pending::Execute { .. })) {
            tracked.pending.pop_front();
        }
    }

    /// ReadyForQuery: the server has resynchronised, so everything queued for
    /// this batch is settled — including expectations an ErrorResponse made
    /// the server skip. Anything left belongs to a batch pipelined behind it.
    pub fn batch_answered(&self) {
        let mut tracked = self.tracked();
        // A ReadyForQuery is proof the backend is not in copy mode: it is the
        // one message copy-in suppresses. This is the backstop for a copy that
        // ended some other way — an ErrorResponse mid-payload, a CopyDone the
        // proxy never saw because the client pipelined past it.
        tracked.copy_in = false;
        while let Some(pending) = tracked.pending.pop_front() {
            if matches!(pending, Pending::Batch) {
                break;
            }
        }
    }
}

fn check_name(what: &'static str, name: &[u8]) -> Result<(), Error> {
    if name.len() > MAX_NAME_LEN {
        return Err(Error::NameTooLong { what, len: name.len(), max: MAX_NAME_LEN });
    }
    Ok(())
}

fn push(tracked: &mut Tracked, pending: Pending) -> Result<(), Error> {
    if tracked.pending.len() >= MAX_PENDING_RESPONSES {
        return Err(Error::SessionLimit {
            what: "outstanding responses",
            limit: MAX_PENDING_RESPONSES,
        });
    }
    tracked.pending.push_back(pending);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rows::tests::{description as positions, transform};

    fn portals() -> Arc<SessionPortals> {
        SessionPortals::new()
    }

    #[test]
    fn a_described_statement_keeps_its_positions_across_later_executes() {
        let portals = portals();
        portals.parse(b"s1", ParamTransforms::default()).unwrap();
        portals.expect_describe(Target::Statement, b"s1").unwrap();
        portals.describe_answered(&positions(2));

        // Another statement is described in between: the previous behaviour
        // kept only this description and lost s1's.
        portals.parse(b"s2", ParamTransforms::default()).unwrap();
        portals.expect_describe(Target::Statement, b"s2").unwrap();
        portals.describe_answered(&positions(0));

        portals.bind(b"", b"s1").unwrap();
        portals.expect_execute(b"").unwrap();
        let RowSource::Portal(found) = portals.row_source() else {
            panic!("s1's own description must be used");
        };
        assert_eq!(found.columns().len(), 2);
    }

    #[test]
    fn an_execute_of_an_undescribed_statement_reports_undescribed() {
        let portals = portals();
        portals.parse(b"s1", ParamTransforms::default()).unwrap();
        portals.bind(b"p", b"s1").unwrap();
        portals.expect_execute(b"p").unwrap();
        assert!(matches!(portals.row_source(), RowSource::Undescribed));
        portals.execute_answered();

        // Describing the portal describes the statement behind it.
        portals.expect_describe(Target::Portal, b"p").unwrap();
        portals.describe_answered(&positions(1));
        portals.expect_execute(b"p").unwrap();
        assert!(matches!(portals.row_source(), RowSource::Portal(_)));
        portals.execute_answered();

        // Re-parsing the name invalidates the description it had.
        portals.parse(b"s1", ParamTransforms::default()).unwrap();
        portals.expect_execute(b"p").unwrap();
        assert!(matches!(portals.row_source(), RowSource::Undescribed));
    }

    #[test]
    fn with_no_execute_outstanding_the_last_description_is_the_authority() {
        let portals = portals();
        assert!(matches!(portals.row_source(), RowSource::LastDescription));
        portals.expect_batch().unwrap();
        assert!(matches!(portals.row_source(), RowSource::LastDescription));
    }

    #[test]
    fn ready_for_query_drops_only_the_batch_that_ended() {
        let portals = portals();
        portals.parse(b"s1", ParamTransforms::default()).unwrap();
        portals.bind(b"", b"s1").unwrap();
        // Batch 1 fails at Parse: its Describe and Execute never get answered.
        portals.expect_describe(Target::Statement, b"s1").unwrap();
        portals.expect_execute(b"").unwrap();
        portals.expect_batch().unwrap();
        // Batch 2 is already pipelined behind it.
        portals.expect_execute(b"").unwrap();
        portals.expect_batch().unwrap();

        portals.batch_answered();
        // Batch 2's Execute is now at the front, not batch 1's leftovers.
        assert!(matches!(portals.row_source(), RowSource::Undescribed));
        portals.describe_answered(&positions(1));
        assert!(
            matches!(portals.row_source(), RowSource::Undescribed),
            "a stale RowDescription must not be attributed to the next batch"
        );
    }

    /// A driver pipelines Bind/Execute/Sync and only then reads the
    /// CopyInResponse, so the Sync reaches a backend that is already in
    /// copy-in mode and ignores it. The marker it queued has to go, or every
    /// later response is attributed to the expectation in front of the one it
    /// answers.
    #[test]
    fn a_sync_the_backend_ignores_during_copy_in_does_not_stay_queued() {
        let portals = portals();
        portals.parse(b"c", ParamTransforms::default()).unwrap();
        portals.bind(b"", b"c").unwrap();
        portals.expect_execute(b"").unwrap();
        portals.expect_batch().unwrap(); // ignored by the backend
        portals.copy_in_started(); // the CopyInResponse the read path saw
        portals.copy_data(COPY_DATA);

        // The copy's own CommandComplete and ReadyForQuery settle it, and the
        // Sync that follows CopyDone is the one that is really answered.
        portals.expect_batch().unwrap();
        portals.execute_answered();
        portals.batch_answered();

        // Nothing is left over, so the next batch lines up.
        portals.expect_describe(Target::Statement, b"c").unwrap();
        portals.describe_answered(&positions(1));
        portals.expect_execute(b"").unwrap();
        assert!(matches!(portals.row_source(), RowSource::Portal(_)));
    }

    /// A simple-protocol `COPY ... FROM STDIN` has no Execute: its
    /// ReadyForQuery is not skipped, so its marker must survive.
    #[test]
    fn copy_data_leaves_a_simple_protocol_batch_alone() {
        let portals = portals();
        portals.expect_batch().unwrap();
        portals.copy_in_started();
        portals.copy_data(COPY_DATA);
        portals.expect_execute(b"nope").unwrap();
        assert!(matches!(portals.row_source(), RowSource::LastDescription));
    }

    /// PostgreSQL discards `d`/`c`/`f` sent outside a copy without answering
    /// them, so acting on one let a client delete a `Batch` marker the backend
    /// still owed a ReadyForQuery for. From there every response settled the
    /// expectation in front of the one it answered, and the next batch's rows
    /// were attributed to the wrong statement — a forced desync any client
    /// could ask for with one stray frame.
    #[test]
    fn a_stray_copy_frame_outside_copy_mode_moves_nothing() {
        let portals = portals();
        // No CopyInResponse has ever been seen, so none of these is payload —
        // before the batch, and again once it is queued.
        for stray in *b"dcf" {
            portals.copy_data(stray);
        }
        portals.parse(b"s1", ParamTransforms::default()).unwrap();
        portals.bind(b"p", b"s1").unwrap();
        portals.expect_describe(Target::Portal, b"p").unwrap();
        portals.expect_execute(b"p").unwrap();
        portals.expect_batch().unwrap();
        for stray in *b"dcf" {
            portals.copy_data(stray);
        }

        // The batch is intact: its Describe still lands on its own Execute...
        portals.describe_answered(&positions(2));
        let RowSource::Portal(found) = portals.row_source() else {
            panic!("a stray copy frame must not disturb this batch's expectations");
        };
        assert_eq!(found.columns().len(), 2);
        // ...and its marker is still there to absorb its own ReadyForQuery,
        // rather than the next batch's.
        portals.execute_answered();
        portals.expect_execute(b"p").unwrap();
        portals.expect_batch().unwrap();
        portals.batch_answered();
        let RowSource::Portal(found) = portals.row_source() else {
            panic!("the following batch's rows must still be attributed to its own statement");
        };
        assert_eq!(found.columns().len(), 2);
    }

    /// The copy ends at CopyDone, so a Sync pipelined *after* it is answered
    /// normally: the flag has to clear, or the next batch's marker would be
    /// dropped as if the backend were still ignoring it.
    #[test]
    fn copy_mode_ends_with_the_copy_and_a_later_sync_is_answered() {
        let portals = portals();
        portals.parse(b"c", ParamTransforms::default()).unwrap();
        portals.bind(b"", b"c").unwrap();
        portals.expect_execute(b"").unwrap();
        portals.expect_batch().unwrap(); // ignored by the backend
        portals.copy_in_started();
        portals.copy_data(COPY_DATA);
        portals.copy_data(b'c'); // CopyDone: the backend is answering again

        // The Sync that follows CopyDone is a real one, and a frame arriving
        // after the copy is a stray again.
        portals.expect_batch().unwrap();
        portals.copy_data(COPY_DATA);
        portals.execute_answered();
        portals.batch_answered();

        portals.expect_describe(Target::Statement, b"c").unwrap();
        portals.describe_answered(&positions(1));
        portals.expect_execute(b"").unwrap();
        assert!(matches!(portals.row_source(), RowSource::Portal(_)));
    }

    #[test]
    fn closing_a_statement_forgets_it_and_its_portals() {
        let portals = portals();
        portals.parse(b"s1", ParamTransforms::default()).unwrap();
        portals.bind(b"p", b"s1").unwrap();
        portals.close_statement(b"s1");
        assert!(portals.bind(b"p2", b"s1").unwrap().is_none());
        portals.expect_execute(b"p").unwrap();
        assert!(matches!(portals.row_source(), RowSource::Undescribed));
    }

    /// The PostgreSQL JDBC driver emits `Close S` for a statement it has
    /// decided not to cache in the *same* batch that executes it, so the whole
    /// batch is on the wire before the first response comes back. Resolving
    /// the Execute's statement by name when the DataRow arrived found nothing
    /// — the entry was already gone — and the resulting `UndescribedRow`
    /// refusal tore down a healthy connection.
    #[test]
    fn a_pipelined_close_does_not_orphan_its_own_execute() {
        let portals = portals();
        // Parse "s1" / Bind "p"→"s1" / Describe "p" / Execute "p" /
        // Close S "s1" / Sync.
        portals.parse(b"s1", ParamTransforms::default()).unwrap();
        portals.bind(b"p", b"s1").unwrap();
        portals.expect_describe(Target::Portal, b"p").unwrap();
        portals.expect_execute(b"p").unwrap();
        portals.close_statement(b"s1");
        portals.expect_batch().unwrap();

        // Only now do the responses arrive.
        portals.describe_answered(&positions(2));
        let RowSource::Portal(found) = portals.row_source() else {
            panic!("the description answered for this Execute must still reach it");
        };
        assert_eq!(found.columns().len(), 2);
    }

    /// The same for a portal closed ahead of its own results, which is the
    /// other half of the pipelined-Close pattern.
    #[test]
    fn a_pipelined_portal_close_does_not_orphan_its_own_execute() {
        let portals = portals();
        portals.parse(b"s1", ParamTransforms::default()).unwrap();
        portals.bind(b"p", b"s1").unwrap();
        portals.expect_describe(Target::Portal, b"p").unwrap();
        portals.expect_execute(b"p").unwrap();
        portals.close_portal(b"p");
        portals.expect_batch().unwrap();

        portals.describe_answered(&positions(3));
        let RowSource::Portal(found) = portals.row_source() else {
            panic!("closing the portal must not orphan the rows already in flight");
        };
        assert_eq!(found.columns().len(), 3);
    }

    /// A description is answered for one incarnation of a name. Re-parsing the
    /// name mid-pipeline must not let the old answer describe the new
    /// statement — the id is what keeps the two apart.
    #[test]
    fn a_reparse_mid_pipeline_does_not_inherit_the_previous_description() {
        let portals = portals();
        portals.parse(b"s1", ParamTransforms::default()).unwrap();
        portals.bind(b"p", b"s1").unwrap();
        portals.expect_describe(Target::Portal, b"p").unwrap();

        // The client re-parses the same name and executes the new statement
        // before reading the first Describe's answer.
        portals.parse(b"s1", ParamTransforms::default()).unwrap();
        portals.bind(b"p", b"s1").unwrap();
        portals.expect_execute(b"p").unwrap();

        portals.describe_answered(&positions(2));
        assert!(
            matches!(portals.row_source(), RowSource::Undescribed),
            "the new statement was never described; the old answer is not its own"
        );
    }

    /// The fix must not weaken the refusal it was narrowing: an Execute of a
    /// statement the server genuinely never described still has nothing to
    /// decrypt with.
    #[test]
    fn an_execute_the_server_never_described_still_reports_undescribed() {
        let portals = portals();
        portals.parse(b"s1", ParamTransforms::default()).unwrap();
        portals.bind(b"p", b"s1").unwrap();
        portals.expect_execute(b"p").unwrap();
        portals.expect_batch().unwrap();
        assert!(matches!(portals.row_source(), RowSource::Undescribed));

        // A Describe answered for a *different* statement does not fill it in.
        let portals = portals_with_two();
        portals.expect_describe(Target::Statement, b"other").unwrap();
        portals.expect_execute(b"p").unwrap();
        portals.describe_answered(&positions(2));
        assert!(
            matches!(portals.row_source(), RowSource::Undescribed),
            "another statement's description must not be back-filled here"
        );
    }

    /// Two statements, with portal "p" bound to the undescribed one.
    fn portals_with_two() -> Arc<SessionPortals> {
        let portals = portals();
        portals.parse(b"other", ParamTransforms::default()).unwrap();
        portals.parse(b"s1", ParamTransforms::default()).unwrap();
        portals.bind(b"p", b"s1").unwrap();
        portals
    }

    #[test]
    fn client_chosen_names_and_pipelines_are_bounded() {
        let portals = portals();
        let long = vec![b'x'; MAX_NAME_LEN + 1];
        assert!(matches!(
            portals.parse(&long, ParamTransforms::default()),
            Err(Error::NameTooLong { .. })
        ));
        assert!(matches!(portals.bind(&long, b"s"), Err(Error::NameTooLong { .. })));

        for i in 0..MAX_PREPARED_STATEMENTS {
            portals.parse(format!("s{i}").as_bytes(), ParamTransforms::default()).unwrap();
        }
        // Re-parsing a known name still works; a new one is refused.
        portals.parse(b"s0", ParamTransforms::default()).unwrap();
        assert!(matches!(
            portals.parse(b"one too many", ParamTransforms::default()),
            Err(Error::SessionLimit { .. })
        ));

        let pipelined = SessionPortals::new();
        for _ in 0..MAX_PENDING_RESPONSES {
            pipelined.expect_batch().unwrap();
        }
        assert!(matches!(pipelined.expect_batch(), Err(Error::SessionLimit { .. })));
    }

    #[test]
    fn one_placeholder_cannot_carry_two_conflicting_actions() {
        let searchable = transform(true);
        let mut params = ParamTransforms::default();
        params
            .record(0, ParamAction::Seal { transform: searchable.clone(), row: RowKeySource::None })
            .unwrap();
        // The same action for the same placeholder is one transform, not two.
        params
            .record(0, ParamAction::Seal { transform: searchable.clone(), row: RowKeySource::None })
            .unwrap();
        assert_eq!(params.iter().count(), 1);

        // Seal and blind-index need different bytes on the wire.
        assert!(matches!(
            params.record(0, ParamAction::SearchIndex(searchable)),
            Err(Error::ConflictingParameter { placeholder: 1 })
        ));
        // A different transform for the same placeholder is a conflict too.
        assert!(matches!(
            params.record(
                0,
                ParamAction::Seal { transform: transform(false), row: RowKeySource::None }
            ),
            Err(Error::ConflictingParameter { placeholder: 1 })
        ));
        assert_eq!(params.iter().count(), 1);
    }
}
