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
//! Every map here is keyed by a client-chosen name, so every one of them is
//! capped — names, statements, portals and outstanding responses (SEC-33).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use dbsec_core::transform::FieldTransform;

use crate::rows::ReadColumn;
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

/// Which positions of a result set are protected, and what the read path does
/// to each. Shared behind an `Arc` because the same description serves every
/// Execute of the statement it belongs to.
pub type Positions = Arc<[(usize, ReadColumn)]>;

/// What Bind must do to one parameter of a prepared statement.
#[derive(Clone)]
pub enum ParamAction {
    /// The parameter feeds a protected column: seal it.
    Seal(Arc<dyn FieldTransform>),
    /// The parameter is compared for equality against a searchable column:
    /// replace it with the blind index (the SQL was rewritten to match the
    /// index prefix).
    SearchIndex(Arc<dyn FieldTransform>),
}

impl ParamAction {
    /// Whether two actions on one parameter ask for the same wire value, and
    /// so can be satisfied by transforming it once.
    fn agrees_with(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Seal(a), Self::Seal(b)) | (Self::SearchIndex(a), Self::SearchIndex(b)) => {
                Arc::ptr_eq(a, b)
            }
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
/// action and rejects a conflicting one, which fails the session rather than
/// writing something no read path can undo (CL-3).
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

/// One prepared statement, as both directions see it.
struct Statement {
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
    Describe(Option<Vec<u8>>),
    /// An Execute of a portal, answered by DataRows plus a completion frame.
    Execute(Option<Vec<u8>>),
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
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
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
        tracked.statements.insert(statement.to_vec(), Statement { params, described: None });
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
        let statement = match target {
            Target::Statement => Some(name.to_vec()),
            // A portal describes the statement it was bound to: every portal
            // of one statement returns the same columns.
            Target::Portal => tracked.portals.get(name).cloned(),
        };
        push(&mut tracked, Pending::Describe(statement))
    }

    /// Records that the server owes the DataRows of `portal`.
    pub fn expect_execute(&self, portal: &[u8]) -> Result<(), Error> {
        let mut tracked = self.tracked();
        let statement = tracked.portals.get(portal).cloned();
        push(&mut tracked, Pending::Execute(statement))
    }

    /// The client is sending a COPY payload, so the backend is in copy-in
    /// mode — where it **ignores Flush and Sync**.
    ///
    /// The Sync that would normally close the batch was already on the wire
    /// before the CopyInResponse came back (drivers pipeline Bind/Execute/Sync
    /// and only then look at the answer), so a batch marker is sitting in the
    /// queue for a ReadyForQuery the backend will never send. Left there it
    /// absorbs the *next* batch's ReadyForQuery, and from then on every
    /// expectation is one response behind — which surfaces as a DataRow the
    /// read path cannot attribute to any portal.
    ///
    /// Only markers queued after the Execute that started the copy are
    /// dropped. A simple-protocol `COPY ... FROM STDIN` has no Execute and its
    /// ReadyForQuery is not skipped, so its marker stays.
    pub fn copy_data(&self) {
        let mut tracked = self.tracked();
        let Some(execute) = tracked.pending.iter().rposition(|p| matches!(p, Pending::Execute(_)))
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
    /// later Execute of that statement knows its protected positions.
    pub fn describe_answered(&self, positions: &Positions) {
        let mut tracked = self.tracked();
        let Some(Pending::Describe(statement)) = tracked.pending.front() else { return };
        let statement = statement.clone();
        tracked.pending.pop_front();
        if let Some(entry) = statement.and_then(|name| tracked.statements.get_mut(&name)) {
            entry.described = Some(positions.clone());
        }
    }

    /// A Describe answered with NoData: the statement returns no rows at all,
    /// which is still a description — an Execute of it must not fall back to
    /// some other statement's positions.
    pub fn no_data(&self) {
        self.describe_answered(&Positions::from(Vec::new()));
    }

    /// Which positions the DataRow now arriving must be decrypted with.
    pub fn row_source(&self) -> RowSource {
        let tracked = self.tracked();
        let Some(Pending::Execute(statement)) = tracked.pending.front() else {
            return RowSource::LastDescription;
        };
        statement
            .as_ref()
            .and_then(|name| tracked.statements.get(name))
            .and_then(|statement| statement.described.clone())
            .map_or(RowSource::Undescribed, RowSource::Portal)
    }

    /// A result set ended: CommandComplete, PortalSuspended or
    /// EmptyQueryResponse.
    pub fn execute_answered(&self) {
        let mut tracked = self.tracked();
        if matches!(tracked.pending.front(), Some(Pending::Execute(_))) {
            tracked.pending.pop_front();
        }
    }

    /// ReadyForQuery: the server has resynchronised, so everything queued for
    /// this batch is settled — including expectations an ErrorResponse made
    /// the server skip. Anything left belongs to a batch pipelined behind it.
    pub fn batch_answered(&self) {
        let mut tracked = self.tracked();
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
    use crate::rows::tests::transform;

    fn positions(count: usize) -> Positions {
        (0..count)
            .map(|i| (i, ReadColumn { transform: Some(transform(false)), mask: None }))
            .collect()
    }

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
        assert_eq!(found.len(), 2);
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
        portals.copy_data();

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
        portals.copy_data();
        portals.expect_execute(b"nope").unwrap();
        assert!(matches!(portals.row_source(), RowSource::LastDescription));
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
        params.record(0, ParamAction::Seal(searchable.clone())).unwrap();
        // The same action for the same placeholder is one transform, not two.
        params.record(0, ParamAction::Seal(searchable.clone())).unwrap();
        assert_eq!(params.iter().count(), 1);

        // Seal and blind-index need different bytes on the wire.
        assert!(matches!(
            params.record(0, ParamAction::SearchIndex(searchable)),
            Err(Error::ConflictingParameter { placeholder: 1 })
        ));
        // A different transform for the same placeholder is a conflict too.
        assert!(matches!(
            params.record(0, ParamAction::Seal(transform(false))),
            Err(Error::ConflictingParameter { placeholder: 1 })
        ));
        assert_eq!(params.iter().count(), 1);
    }
}
