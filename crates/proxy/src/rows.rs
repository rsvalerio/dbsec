//! The read path: RowDescription/DataRow interception in the upstream→client
//! relay. Configured columns are matched by table OID + attnum; values in a
//! transform's stored form are opened, then masked when a mask is configured.
//! Everything else passes through untouched. Crypto errors fail the session —
//! never a silent passthrough of ciphertext.
//!
//! Which positions of a DataRow are protected is *not* simply "whatever the
//! last RowDescription said". In the extended protocol the server describes a
//! statement when it is asked to (Describe), not when it is executed, so the
//! DataRows of a cached prepared statement arrive with no RowDescription in
//! front of them. Positions are therefore keyed to the portal being executed,
//! which only the client→upstream direction can see; [`crate::portal`] is the
//! state the two directions share to keep them in agreement, and a DataRow
//! whose columns nothing on the connection identifies fails the session
//! instead of relaying possibly-protected values (CL-3). Nor are those
//! positions frozen once captured: a cached statement may never be described
//! again, so what the Describe recorded is the *fields*, and the mapping is
//! recomputed whenever the resolution behind it has moved on ([`Described`]).
//!
//! *Which* columns are protected is keyed differently here than on the write
//! path, and the difference matters. `encrypt::WriteCatalog` matches by
//! `(schema, table, column)` **name**, resolved from the SQL text of every
//! statement; this module matches by `(table_oid, attnum)`, resolved against
//! the catalog by [`crate::resolve`]. Names survive a migration and OIDs do
//! not, so a `DROP TABLE`/`CREATE TABLE` or a dropped-and-re-added column
//! leaves the write path still sealing and this path recognising nothing —
//! the failure that leaks. [`Resolved`] is therefore a snapshot that the
//! refresher replaces, not a startup constant, and
//! [`RowDecryptor::check_for_stale_mapping`] is what makes a session notice
//! the gap between two refreshes (CL-3).
//!
//! # Refusals
//!
//! This path has eleven of them. Five concern a column whose protection the
//! proxy cannot vouch for: a DataRow no described statement covers
//! ([`Error::UndescribedRow`]), a result column a stale mapping would
//! under-match ([`Error::StaleColumnMap`]), a result column named like a
//! protected one that carries no table identity at all
//! ([`Error::ComputedProtectedColumn`]) — a cast, an expression or a subquery
//! output, which PostgreSQL describes with `table_oid = 0` so no mapping can
//! ever cover it — a result of the legacy function-call fast path
//! ([`Error::FunctionCallResult`]), which bypasses SQL entirely and so arrives
//! with no column identity of any kind, and a protected value larger than
//! `max_protected_value_bytes` ([`DEFAULT_MAX_PROTECTED_VALUE_LEN`] unless the
//! operator says otherwise), which is refused rather than decrypted because
//! opening it costs several times its own size in transient memory (SEC-33).
//! The middle three are gated on `on_unprotected = "reject"`; the size ceiling,
//! like the undescribed row, is not.
//!
//! Six more come from row binding and from the size ceiling's sibling: a row
//! whose rewrite outgrows what a frame header can express
//! ([`Error::FrameTooLarge`], the other half of the same memory policy), a
//! row-bound value whose row key the query never projected
//! ([`dbsec_core::Error::RowKeyMissing`]), a projected row key the proxy
//! cannot canonicalise — NULL, not UTF-8, a wrong-width binary integer
//! ([`dbsec_core::Error::RowKeyType`]), and the two halves of the self-join problem, which
//! no RowDescription can disambiguate (SEC-11): a result set projecting one
//! row-keyed table's key *more than once* ([`Error::AmbiguousRowKey`]),
//! refused on sight because the alternative is opening one row's value against
//! another row's key; and one projecting the key once and a protected column
//! more than once ([`Error::AmbiguousRowInstance`]), which is indistinguishable
//! from `SELECT ssn, ssn FROM users` until a value fails to authenticate, and
//! so is refused only then; and a cell-only value in a column whose table has
//! closed its row-binding migration window
//! ([`dbsec_core::Error::RowBindingDowngraded`]), where the bytes are intact
//! but bound to less than the configuration promises. All six are the client's
//! or the operator's to fix, which is what makes them refusals rather than
//! session failures; [`is_refusal`] is the single list, and the count above is
//! the length of it. They hand the
//! client a PostgreSQL
//! ErrorResponse (SQLSTATE 42501, the same one a refused write carries) and
//! then end the session — see [`RowDecryptor::on_frame`] for why the read path
//! cannot refuse at statement level the way the write path does: its statement
//! has already run, and only closing the connection stops what the backend is
//! still executing behind it. Crypto failures are not refusals and still fail
//! the session.
//!
//! Whether the second one deserves a knob of its own, separate from
//! `on_unprotected`, was decided here rather than left open: **it does not**.
//! `on_unprotected` is not a write-path setting that the read path borrowed —
//! it is the one answer to "this may be unprotected, would you rather have an
//! error than a guess", and both paths are asking exactly that question about
//! the same columns. Splitting it would let a deployment be strict about
//! writing plaintext and lax about handing back stored bytes, which is the
//! half-enforced state the setting exists to rule out; and the operator who
//! turns on `reject` has to reason about one behaviour instead of two. A
//! separate knob only earns its place if a real deployment needs the mixed
//! mode, and none has asked.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dbsec_core::envelope::RowKey;
use dbsec_core::mask::MaskSpec;
use dbsec_core::sync::Unpoisoned as _;
use dbsec_core::transform::{FieldTransform, WireForm};
use dbsec_pgwire as pgwire;

use tokio::sync::Notify;

use crate::config::OnUnprotected;
use crate::portal::{Positions, ResultFormats, RowSource, SessionPortals};
use crate::session::FrameAction;
use crate::Error;

/// Default for `max_protected_value_bytes`: the largest wire value the read
/// path will decrypt, mask and re-encode for a single protected column.
///
/// Field-level encryption protects fields — emails, identifiers, notes — so
/// this ceiling sits orders of magnitude above anything a configured
/// column realistically holds while keeping the decrypt path's allocation
/// amplification (see [`RowDecryptor::decrypt_row`]) bounded to tens of MiB
/// rather than the several GiB a value near the 1 GiB frame cap would cost.
/// A value over it is refused rather than relayed: passing it through would
/// hand the client a protected column's stored form, which is the one thing
/// this module never does.
///
/// It is only the *default* because the failure it produces is a hard one — an
/// ErrorResponse and a closed session, on the read path, naming a limit the
/// operator would otherwise have to rebuild the binary to change. A deployment
/// that really does encrypt a column holding documents or images raises
/// `max_protected_value_bytes` and accepts the memory that costs; nothing about
/// 16 MiB is a safety property, only a bound on the amplification.
pub const DEFAULT_MAX_PROTECTED_VALUE_LEN: usize = 16 * 1024 * 1024;

/// The two size bounds [`RowDecryptor::decrypt_row`] enforces while it
/// rewrites one DataRow. Grouped because they are one policy — how much
/// transient memory a single row may cost — and because passing them
/// separately would make the function's signature a row of bare `usize`s
/// (FN-3, FN-4).
#[derive(Debug, Clone, Copy)]
struct Bounds {
    /// Largest single protected value that will be opened, from
    /// `max_protected_value_bytes`.
    max_value: usize,
    /// Largest re-encoded body the rewritten row may reach.
    max_body: usize,
}

/// What the read path does to one column: open with the transform (when
/// present and readable), then mask what the client would see.
#[derive(Clone)]
pub struct ReadColumn {
    /// The configured column's qualified `schema.table.column` name.
    ///
    /// Carried for diagnostics, and for one diagnostic in particular: a
    /// row-bound value that fails to authenticate is the only externally
    /// visible product of row binding, and an alarm that cannot say which cell
    /// fired is close to no alarm at all (READ-8). Nothing else on this path
    /// knows the name — the mapping is keyed by `(table_oid, attnum)`, and a
    /// RowDescription's own field label is the *result set's* alias, not the
    /// column's identity.
    ///
    /// `Arc<str>` rather than `String` because a `ReadColumn` is cloned into
    /// every [`Described`] and again on every re-derivation; the name is
    /// fixed at resolution time and never edited.
    pub name: Arc<str>,
    pub transform: Option<Arc<dyn FieldTransform>>,
    pub mask: Option<MaskSpec>,
}

/// Configured columns keyed by `(table oid, attnum)`, as resolved by one run
/// of [`crate::resolve::resolve_columns`].
pub type ColumnMap = HashMap<(u32, i16), ReadColumn>;

/// One resolution of the configured columns against the live catalog.
///
/// The read path matches by `(table_oid, attnum)` while the write path matches
/// by *name*, so the two disagree the moment a migration moves a column: a
/// recreated table gets a new `pg_class.oid`, and a dropped-and-re-added column
/// gets a new `attnum` (PostgreSQL never reuses one). The write path keeps
/// sealing, the read path stops finding anything, and the client is handed
/// stored bytes. That is why this is a *snapshot* that gets replaced rather
/// than a value resolved once for the process lifetime (CL-3), and why it
/// carries the two extra sets below: they are what lets a session notice the
/// mismatch before the next refresh does.
#[derive(Default)]
pub struct Resolved {
    pub columns: ColumnMap,
    /// Lowercased names of every configured column — the only thing a
    /// RowDescription field can be matched against by name, since the message
    /// identifies a field's table by OID and never by name.
    pub names: HashSet<String>,
    /// Where each configured column resolved to, by qualified name, so a
    /// re-resolution can name what moved instead of only which OID did.
    pub positions: HashMap<String, (u32, i16)>,
    /// Each protected table's declared row key, by table OID. Absent means the
    /// table has no `[[table]] row_key`, which is the default and keeps
    /// cell-only binding.
    pub row_keys: HashMap<u32, ResolvedRowKey>,
    /// The same declarations keyed by `(schema, table)`, lowercased, for the
    /// write path — which matches by name, not by OID, and so cannot use the
    /// map above. Both are built from one resolution, so the two directions
    /// cannot disagree about which column names a row.
    pub row_key_by_table: HashMap<(String, String), ResolvedRowKey>,
    /// Which resolution this is, counting from the one built at startup.
    ///
    /// Assigned by [`RowContext::publish`] and ignored on the way in, so a
    /// caller building a `Resolved` never has to know about it. It exists so a
    /// [`Described`] can say which resolution it was computed against — see
    /// [`Described::rederived`].
    pub generation: u64,
}

/// Where one protected field's row key sits in the *result set* it came back
/// in, and how to read it.
#[derive(Debug, Clone)]
pub enum RowKeyRef {
    /// The field's table declares no row key, and also the case where it
    /// declares one the query did not project. Those two are deliberately not
    /// distinguished: the stored value decides whether a key was needed, so a
    /// `DBS2` value written before the table gained a key still opens, while a
    /// `DBS3` value reports [`dbsec_core::Error::RowKeyMissing`] from the
    /// envelope itself. Deciding it here instead would mean guessing at the
    /// version.
    Absent,
    /// The key is the result column at `index`, canonicalised as `type_oid`.
    /// The *format* those bytes arrived in is not recorded here — it belongs
    /// to the Bind, not to the description ([`crate::portal::ResultFormats`]).
    Slot { index: usize, type_oid: u32 },
    /// The result set projects this table's row key more than once, which a
    /// self-join does: `SELECT a.id, a.ssn, b.id, b.ssn FROM users a JOIN
    /// users b …` gives `b.ssn` the same `(table_oid, attnum)` identity as
    /// `a.ssn`, and RowDescription carries nothing that tells two instances of
    /// one relation apart. Taking the first match would open `b.ssn` against
    /// `a.id`'s key, which fails as a decrypt error — the signal a *relocated*
    /// value produces — on ordinary SQL. So the ambiguity is named instead
    /// (SEC-11).
    Ambiguous { table: String, column: String },
    /// The result set describes this table's row key as a *different type*
    /// from the one the catalog resolved. `ALTER TABLE users ALTER COLUMN id
    /// TYPE …` is the case: the write path keeps canonicalising through the
    /// resolved type while `RowDescription` announces the new one, so the two
    /// directions silently derive different keys and every value already
    /// stored stops opening. Named rather than resolved to either type
    /// (SEC-11).
    TypeChanged { table: String, column: String, wire: u32, resolved: u32 },
}

/// Where a table's declared row key lives, once resolved against the catalog.
///
/// The type OID is carried because a row key has to be canonicalised before it
/// can be bound, and the wire bytes alone do not say how (see
/// [`dbsec_core::rowkey`]). The names are kept for messages: a refusal that says
/// which column of which table the client has to project (or stop projecting
/// twice) is actionable, one that says "attnum 1 of oid 16384" is not.
#[derive(Debug, Clone)]
pub struct ResolvedRowKey {
    pub attnum: i16,
    pub type_oid: u32,
    pub name: String,
    /// Qualified `schema.table`, as declared.
    pub table: String,
}

impl Resolved {
    /// Which positions of a result set whose fields resolve to
    /// `(table_oid, attnum)` are protected, and what to do with each.
    fn protected(&self, fields: &[(u32, i16, u32)]) -> Vec<(usize, ReadColumn, RowKeyRef)> {
        fields
            .iter()
            .enumerate()
            .filter_map(|(index, (table_oid, attnum, _))| {
                let column = self.columns.get(&(*table_oid, *attnum))?.clone();
                Some((index, column, self.row_key_ref(*table_oid, fields)))
            })
            .collect()
    }

    /// Which field of this result set carries the row key for `table_oid`.
    ///
    /// Matched on `(table_oid, attnum)` like everything else on this path, so a
    /// same-named column of another table in a join cannot be mistaken for it
    /// — and a *second* match is reported as ambiguous rather than resolved to
    /// the first, because within one table's own OID the message says nothing
    /// about which instance of it a field came from.
    fn row_key_ref(&self, table_oid: u32, fields: &[(u32, i16, u32)]) -> RowKeyRef {
        let Some(declared) = self.row_keys.get(&table_oid) else { return RowKeyRef::Absent };
        let mut matches = fields
            .iter()
            .enumerate()
            .filter(|(_, (oid, attnum, _))| *oid == table_oid && *attnum == declared.attnum);
        let Some((index, (_, _, type_oid))) = matches.next() else { return RowKeyRef::Absent };
        if matches.next().is_some() {
            return RowKeyRef::Ambiguous {
                table: declared.table.clone(),
                column: declared.name.clone(),
            };
        }
        if *type_oid != declared.type_oid {
            return RowKeyRef::TypeChanged {
                table: declared.table.clone(),
                column: declared.name.clone(),
                wire: *type_oid,
                resolved: declared.type_oid,
            };
        }
        RowKeyRef::Slot { index, type_oid: *type_oid }
    }
}

/// What one RowDescription said, kept for every later Execute of the statement
/// it described.
///
/// The positions alone are not enough. In the extended protocol a driver
/// describes a statement once and then executes it from its cache forever, so
/// the DataRows of that statement arrive with no `'T'` in front of them and
/// nothing re-derives the mapping. A column whose protection is *added* after
/// the Describe — an operator config change, or a re-resolution that had
/// captured nothing because the column did not exist yet — would then be
/// relayed in its stored form for the life of the statement, silently under
/// `warn` and with no `'T'` for `reject` to catch either.
///
/// So the field identities are kept alongside, with the generation of the
/// resolution the positions came out of. When the resolution moves on, the
/// mapping is recomputed from the fields rather than trusted (CL-3).
///
/// The default is the empty description a `NoData` reply leaves behind: no
/// fields, no protected positions, and nothing a re-derivation could change.
#[derive(Default)]
pub struct Described {
    /// The resolution [`Self::columns`] was computed against.
    generation: u64,
    /// `(table_oid, attnum, type_oid)` of every field of the RowDescription,
    /// in order — the only part of it a later re-derivation needs. Ten bytes
    /// per result column, held once per described statement. The type OID is
    /// carried for the row key alone: a value the proxy has to *interpret*
    /// rather than relay, which its bytes do not describe. The field's format
    /// code is deliberately not kept — for a Describe of a statement the
    /// protocol says it is always zero, so the Bind is the only authority on
    /// it (see [`crate::portal::ResultFormats`]).
    fields: Box<[(u32, i16, u32)]>,
    /// The protected positions of that result set, each with where its row key
    /// sits in the same row.
    columns: Vec<(usize, ReadColumn, RowKeyRef)>,
}

impl Described {
    fn new(resolved: &Resolved, fields: impl Iterator<Item = (u32, i16, u32)>) -> Self {
        let fields: Box<[(u32, i16, u32)]> = fields.collect();
        Self { generation: resolved.generation, columns: resolved.protected(&fields), fields }
    }

    /// The same result set's positions against a newer resolution.
    ///
    /// The mapping only ever *grows*. A newly covered position is taken from
    /// the new resolution — that is the whole point — but a position this
    /// description already protects keeps what it was described with, even
    /// when the new resolution no longer covers it. That case is a column
    /// whose `(table_oid, attnum)` moved, and the rows of this cached
    /// statement are still in the form the old transform opens (the envelope
    /// keys by key id, not by OID), so dropping it would relay stored bytes
    /// where the frozen mapping decrypted them. Growing only is what makes
    /// re-derivation strictly safer than freezing.
    fn rederived(&self, resolved: &Resolved) -> Self {
        let mut columns = resolved.protected(&self.fields);
        for (index, column, slot) in &self.columns {
            if !columns.iter().any(|(covered, _, _)| covered == index) {
                columns.push((*index, column.clone(), slot.clone()));
            }
        }
        columns.sort_unstable_by_key(|(index, _, _)| *index);
        Self { generation: resolved.generation, columns, fields: self.fields.clone() }
    }

    pub fn columns(&self) -> &[(usize, ReadColumn, RowKeyRef)] {
        &self.columns
    }
}

/// Shared, per-process state for the decrypt path.
///
/// `resolved` is swapped by the refresher ([`crate::resolve::refresh_loop`]),
/// so a long-lived session picks up a re-resolution without reconnecting: at
/// its next RowDescription, and — because a cached prepared statement may
/// never send another one — at the next Execute of anything already described
/// ([`Described::rederived`]). The lock is taken for a clone of one `Arc` and
/// never across an `.await`.
pub struct RowContext {
    resolved: std::sync::RwLock<Arc<Resolved>>,
    /// The generation of `resolved`, published *after* it and readable without
    /// the lock.
    ///
    /// Every DataRow of a cached statement has to ask "is the mapping I was
    /// described with still current"; taking the resolution lock per row to
    /// answer it would put a lock acquisition on the hottest path there is.
    /// Publishing this second is what makes the unsynchronised read safe: a
    /// session that sees the old value merely re-asks on the next row, whereas
    /// seeing the new value while reading the old resolution would stamp a
    /// stale re-derivation as current and never look again.
    generation: std::sync::atomic::AtomicU64,
    /// What a session does when a RowDescription looks like it was resolved
    /// against a schema that has since changed: warn, or fail the session.
    on_unprotected: OnUnprotected,
    /// The configured per-value read-path ceiling
    /// (`max_protected_value_bytes`, defaulting to
    /// [`DEFAULT_MAX_PROTECTED_VALUE_LEN`]). Carried here rather than read as a
    /// constant so a deployment whose protected columns hold more than the
    /// default has something to set (validated at load time by
    /// `Config::validate`).
    max_protected_value_len: usize,
    /// Woken by a session that saw a suspect field, so a migration is picked
    /// up at the first read that notices it rather than at the next tick.
    refresh: Notify,
}

impl RowContext {
    pub fn new(
        mut resolved: Resolved,
        on_unprotected: OnUnprotected,
        max_protected_value_len: usize,
    ) -> Self {
        resolved.generation = 0;
        Self {
            resolved: std::sync::RwLock::new(Arc::new(resolved)),
            generation: std::sync::atomic::AtomicU64::new(0),
            on_unprotected,
            max_protected_value_len,
            refresh: Notify::new(),
        }
    }

    /// The current resolution. A poisoned lock means a session task panicked
    /// while holding it, which it can only have done between a clone and a
    /// swap — the value is intact either way.
    pub fn resolved(&self) -> Arc<Resolved> {
        self.resolved.read().unpoisoned().clone()
    }

    /// Publishes a fresh resolution to every live session, under the next
    /// generation — which is what tells a cached statement's positions they
    /// are out of date.
    pub fn publish(&self, mut resolved: Resolved) {
        use std::sync::atomic::Ordering;
        let mut slot = self.resolved.write().unpoisoned();
        let generation = slot.generation.saturating_add(1);
        resolved.generation = generation;
        *slot = Arc::new(resolved);
        drop(slot);
        // After the swap, deliberately: see the field's own comment.
        self.generation.store(generation, Ordering::Release);
    }

    /// The generation a description has to match to still be current.
    fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Resolves as soon as the refresher is next scheduled.
    pub async fn refresh_requested(&self) {
        self.refresh.notified().await;
    }

    /// Asks the refresher to re-resolve now. Coalescing is `Notify`'s own: a
    /// burst of sessions all noticing the same migration wakes it once.
    fn request_refresh(&self) {
        self.refresh.notify_one();
    }

    pub fn decryptor(self: &Arc<Self>, portals: Arc<SessionPortals>) -> RowDecryptor {
        RowDecryptor {
            ctx: self.clone(),
            portals,
            described: None,
            warned_stale: false,
            warned_computed: false,
            warned_function_call: false,
        }
    }
}

/// Per-session read state. `described` holds the positions of the most recent
/// RowDescription, which is the authority for the *simple* protocol only; in
/// the extended protocol the portal being executed decides, and `portals` is
/// what knows which portal that is.
pub struct RowDecryptor {
    ctx: Arc<RowContext>,
    portals: Arc<SessionPortals>,
    described: Option<Positions>,
    /// Whether this session has already reported a suspect field. One line per
    /// session is enough to act on; one per result set would be a log flood
    /// for exactly as long as the migration goes unnoticed.
    warned_stale: bool,
    warned_computed: bool,
    warned_function_call: bool,
}

/// Whether an error is a refusal the client can be told about, rather than a
/// failure of the session itself. Every variant means "these bytes may be a
/// protected column's stored form and the proxy will not relay them" — a
/// policy decision about one result set, which is exactly what an
/// ErrorResponse expresses. Anything else (a decrypt failure, a malformed
/// frame) says the stream is not what it claims to be, and the session ends.
fn is_refusal(error: &Error) -> bool {
    matches!(
        error,
        Error::UndescribedRow
            | Error::StaleColumnMap { .. }
            | Error::ComputedProtectedColumn { .. }
            | Error::FunctionCallResult
            | Error::ProtectedValueTooLarge { .. }
            // The other half of the same policy. `Bounds::max_value` and
            // `Bounds::max_body` both answer "how much transient memory may
            // one row cost", and inside `on_frame` this variant has exactly
            // one producer: `decrypt_row` refusing a rewrite that outgrew its
            // frame. Leaving it fatal made one bound answer the client and the
            // other drop the socket with nothing sent — the same "policy
            // refusal read as a network fault" this path exists to avoid
            // (ERR-1). Both now say the same thing to the operator: a
            // configured limit refused this result set.
            | Error::FrameTooLarge { .. }
            // A result set that projects one row-keyed table twice, which the
            // client fixes by projecting the key once — its query, its repair.
            | Error::AmbiguousRowKey { .. }
            // The same repair from the other side: the key came back once and
            // the protected column more than once, so the query is a self-join
            // the description cannot resolve. Refused rather than fatal because
            // the fix is again the client's — query each instance separately.
            | Error::AmbiguousRowInstance { .. }
            // A row-bound value whose row key the query did not project. The
            // client is answered rather than the session merely failing,
            // because the fix is theirs: select the table's row key. Relaying
            // the stored bytes instead is the disclosure this whole path
            // exists to prevent.
            | Error::Wire(dbsec_core::Error::RowKeyMissing)
            // A declared row key the proxy cannot canonicalise: NULL, not
            // UTF-8, a binary integer of the wrong width, an unknown format
            // code. Distinct from `RowKeyMissing`, which means the query never
            // projected the column at all — this one means it did and the
            // value cannot name a row. Both are the client's to fix, and
            // neither is evidence the ciphertext was tampered with, so the
            // value is refused rather than the session merely failing.
            | Error::Wire(dbsec_core::Error::RowKeyType(_))
            // A cell-only value in a column whose table closed its row-binding
            // migration window. Also a policy decision about one result set:
            // the bytes are intact, they are simply bound to less than the
            // configuration promises, and relaying them would report
            // protection that is not there. The remedy is the operator's —
            // re-encrypt the value, or reopen the window — so the client is
            // told why rather than seeing a dropped socket.
            | Error::Wire(dbsec_core::Error::RowBindingDowngraded)
    )
}

impl RowDecryptor {
    /// Inspects one upstream→client frame and says what the relay does with
    /// it.
    ///
    /// A *refusal* — a DataRow no described statement covers, a result column
    /// a stale mapping would under-match or a function-call fast-path result
    /// under `on_unprotected = "reject"`, or a protected value over
    /// `max_protected_value_bytes` — hands the client
    /// the same PostgreSQL ErrorResponse a refused write carries, and then
    /// ends the session.
    ///
    /// The error is the point: dropping the socket silently (the behaviour
    /// before this path had one) gave the client `Closed` rather than a
    /// `DbError`, so a policy refusal read as a network fault and the proxy's
    /// reason stayed in its log.
    ///
    /// Ending the session is equally the point, and is why this is not the
    /// statement-level refusal the write path performs. A refused *write* never
    /// reaches the backend. A refused *read* is the result of a statement that
    /// has already run, and the backend is still working through whatever
    /// followed it in the batch. Answering the client and resynchronising on
    /// the backend's own ReadyForQuery leaves `SELECT protected; UPDATE …` to
    /// commit its UPDATE behind an error that told the client nothing
    /// happened — and the relayed ReadyForQuery even carries the backend's
    /// real `I` status to confirm it. Nothing the proxy can send in-band stops
    /// a batch already executing, so the connection closes and the backend
    /// rolls the implicit transaction back.
    ///
    /// Every *other* error is still fatal to the session: a decrypt failure
    /// means the bytes in flight are not what they claim to be, and there is
    /// no state to resynchronise to.
    pub fn on_frame(&mut self, msg_type: u8, body: &[u8]) -> Result<FrameAction, Error> {
        match self.inspect(msg_type, body) {
            Ok(None) => Ok(FrameAction::Relay),
            Ok(Some(body)) => Ok(FrameAction::Replace(body)),
            Err(error) if is_refusal(&error) => Ok(self.refuse(&error)),
            Err(error) => Err(error),
        }
    }

    /// Answers the client with an ErrorResponse and ends the session, which is
    /// what stops the rest of the batch upstream.
    fn refuse(&mut self, error: &Error) -> FrameAction {
        tracing::error!(
            error = %error,
            "refusing this result set; answering the client and closing the session"
        );
        FrameAction::RefuseAndClose(crate::encrypt::error_response(&format!(
            "dbsec refused to relay this result: {error}"
        )))
    }

    /// One frame's decryption: a replacement body, or `None` to relay it
    /// untouched.
    fn inspect(&mut self, msg_type: u8, body: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match msg_type {
            b'T' => {
                let fields = pgwire::parse_row_description(body)?;
                let resolved = self.ctx.resolved();
                let positions: Positions = Arc::new(Described::new(
                    &resolved,
                    fields.iter().map(|f| (f.table_oid, f.attnum, f.type_oid)),
                ));
                self.check_for_stale_mapping(&fields, &resolved, &positions)?;
                // Whichever Describe asked for this keeps it, so every later
                // Execute of that statement decrypts the right positions.
                self.portals.describe_answered(&positions);
                self.described = Some(positions);
                Ok(None)
            }
            b'n' => {
                self.portals.no_data();
                self.described = None;
                Ok(None)
            }
            b'D' => {
                // The formats come from the portal's Bind, which is the only
                // message that states them; a simple-protocol result set has
                // no Bind and is all text, which is the default (SEC-31).
                let (positions, formats) = match self.portals.row_source() {
                    // A cached statement's description can be arbitrarily old,
                    // so it is checked against the current resolution before
                    // it is used; a simple-protocol description was built from
                    // the `'T'` immediately in front of these rows.
                    RowSource::Portal(positions, formats) => (self.current(positions), formats),
                    RowSource::LastDescription => match &self.described {
                        Some(positions) => (positions.clone(), ResultFormats::default()),
                        None => return Err(Error::UndescribedRow),
                    },
                    RowSource::Undescribed => return Err(Error::UndescribedRow),
                };
                if positions.columns().is_empty() {
                    return Ok(None);
                }
                // `- 4` because the frame header's length field counts itself:
                // the same arithmetic `session::encode_frame_header` inverts.
                Self::decrypt_row(
                    positions.columns(),
                    &formats,
                    body,
                    Bounds {
                        max_value: self.ctx.max_protected_value_len,
                        max_body: pgwire::MAX_MESSAGE_LEN - 4,
                    },
                )
            }
            // A result set ended. `described` is dropped with it so a later
            // DataRow can never inherit these positions by accident.
            b'C' | b'I' | b's' | b'E' => {
                self.portals.execute_answered();
                self.described = None;
                Ok(None)
            }
            b'Z' => {
                self.portals.batch_answered();
                self.described = None;
                Ok(None)
            }
            b'V' => self.function_call_result(),
            _ => Ok(None),
        }
    }

    /// The positions to decrypt a cached statement's rows with, re-derived
    /// when the resolution has moved since the Describe that captured them.
    ///
    /// This is the window the refresher's "picked up at the next
    /// RowDescription" model does not close. A driver with a prepared-statement
    /// cache describes a statement once and then sends only Bind/Execute, so
    /// there may never *be* a next RowDescription; a column whose protection is
    /// added afterwards would be relayed in its stored form for as long as the
    /// statement lives (CL-3). The field identities kept in [`Described`] are
    /// enough to answer the question without one.
    ///
    /// The re-derivation is written back, so it costs one pass over the fields
    /// per Execute rather than one per row, and it is not a refusal: the new
    /// mapping is the *correct* answer, so there is nothing to refuse. The
    /// name heuristics of [`Self::check_for_stale_mapping`] are not re-run
    /// either, and cannot be — a `Described` keeps field identities, not field
    /// names. Nothing is lost by that: those heuristics exist to notice a
    /// mapping that stopped covering a column, and re-derivation never drops a
    /// mapping, so a cached statement keeps decrypting exactly as it did.
    fn current(&self, positions: Positions) -> Positions {
        if positions.generation == self.ctx.generation() {
            return positions;
        }
        let resolved = self.ctx.resolved();
        let refreshed = Arc::new(positions.rederived(&resolved));
        self.portals.rederived(&refreshed);
        refreshed
    }

    /// The legacy fast path's answer (`FunctionCall` `'F'` →
    /// `FunctionCallResponse` `'V'`), which is a result this module cannot
    /// place.
    ///
    /// The fast path invokes a function by OID with binary arguments and no
    /// SQL at all, so the rewriter never sees it and there is no
    /// RowDescription behind it: the reply is one bare value, and nothing on
    /// the connection says which column it came out of. A function that reads
    /// a protected column — `lo_get`, a custom accessor, a `SECURITY DEFINER`
    /// reader — therefore hands the client the column's stored form:
    /// `blind_index || envelope` for an encrypted column, and the *unmasked*
    /// value for a mask-only one.
    ///
    /// It is the same question `on_unprotected` answers everywhere else —
    /// "this may be unprotected, would you rather have an error than a guess"
    /// — so it is answered by the same switch rather than by a catch-all
    /// relay. Under `reject` the result is refused; under `warn` it is
    /// relayed, once per session, with a line saying so.
    fn function_call_result(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.ctx.on_unprotected == OnUnprotected::Reject {
            return Err(Error::FunctionCallResult);
        }
        if !self.warned_function_call {
            self.warned_function_call = true;
            tracing::warn!(
                "the client used the legacy function-call fast path; its result carries no column \
                 identity, so it cannot be decrypted or masked and is being relayed as stored"
            );
        }
        Ok(None)
    }

    /// Notices a RowDescription that a stale `(table_oid, attnum)` mapping
    /// would silently under-match.
    ///
    /// A field is *suspect* when it comes from a real table (`table_oid != 0`,
    /// so not a computed expression), its name is one of the configured column
    /// names, and nothing in the current resolution covers its position. After
    /// `DROP TABLE t; CREATE TABLE t (...)` or `ALTER TABLE t DROP COLUMN c,
    /// ADD COLUMN c ...` that is exactly what the protected column looks like:
    /// the write path still seals it by name, and the read path no longer
    /// recognises it, so the client is handed `blind_index || envelope` bytes
    /// with no error anywhere (CL-3).
    ///
    /// The name match is a heuristic, and it is the only one available: a
    /// RowDescription names its fields but identifies their table only by OID.
    /// An unrelated table with a same-named column therefore also trips it.
    /// That is why it *requests a re-resolution* — which settles the question
    /// authoritatively, and which is the actual repair — and why the
    /// fail-closed reading is behind `on_unprotected = "reject"`, the same
    /// switch the write path uses for "this may be unprotected, and I would
    /// rather error than guess".
    fn check_for_stale_mapping(
        &mut self,
        fields: &[pgwire::RowField<'_>],
        resolved: &Resolved,
        positions: &Positions,
    ) -> Result<(), Error> {
        let covered: HashSet<usize> =
            positions.columns().iter().map(|(index, _, _)| *index).collect();
        let named_like_protected = |field: &pgwire::RowField<'_>| {
            std::str::from_utf8(field.name)
                .is_ok_and(|name| resolved.names.contains(&name.to_lowercase()))
        };

        // A field with no table identity that is still named like a protected
        // column: a cast or a subquery output, which keeps the column's name
        // but loses its OID. Nothing to re-resolve — there is no mapping that
        // could ever cover it — so this is reported on its own terms.
        //
        // The write path refuses the shapes it can see in the statement, and
        // it now carries a derived table's output columns into the enclosing
        // scope, so `SELECT lower(email) FROM (SELECT email FROM users) s` is
        // decided there. What still surfaces only here is the shape that keeps
        // the name while losing the OID and computes nothing the statement can
        // be resolved against — a cast, or a subquery output the walk could not
        // attribute to a protected relation.
        //
        // The reverse gap is why this is a backstop and not the check: the
        // match is on the field *name*, and PostgreSQL names the output of
        // `SELECT lower(email) FROM users` `lower`, not `email`. A cast keeps
        // the name and is caught here; a function call is not, and never can
        // be. Anything computed over a relation in the statement's own scope —
        // base table or derived — is therefore decided by the write path
        // (`encrypt::scope::computed_protected_column`), which still has the
        // column name in front of it.
        let computed = fields.iter().enumerate().find(|(index, field)| {
            field.table_oid == 0 && !covered.contains(index) && named_like_protected(field)
        });
        if let Some((_, field)) = computed {
            let column = String::from_utf8_lossy(field.name).into_owned();
            if self.ctx.on_unprotected == OnUnprotected::Reject {
                return Err(Error::ComputedProtectedColumn { column });
            }
            if !self.warned_computed {
                self.warned_computed = true;
                tracing::warn!(
                    column,
                    "a result column named like a protected column carries no table identity; it \
                     is computed or comes from a subquery, so it cannot be decrypted or masked and \
                     is being relayed in its stored form"
                );
            }
        }

        let suspect = fields.iter().enumerate().find(|(index, field)| {
            field.table_oid != 0 && !covered.contains(index) && named_like_protected(field)
        });
        let Some((_, field)) = suspect else { return Ok(()) };
        // The refresher settles it either way: a real migration re-resolves
        // the column, and a false positive costs one catalog round-trip.
        self.ctx.request_refresh();
        let column = String::from_utf8_lossy(field.name).into_owned();
        if self.ctx.on_unprotected == OnUnprotected::Reject {
            return Err(Error::StaleColumnMap { column, table_oid: field.table_oid });
        }
        if !self.warned_stale {
            self.warned_stale = true;
            tracing::warn!(
                column,
                table_oid = field.table_oid,
                attnum = field.attnum,
                "a result column named like a protected column is not in the resolved column map; \
                 the table or column may have been recreated since startup, in which case writes \
                 are still being encrypted and reads are relaying stored values — re-resolving"
            );
        }
        Ok(())
    }

    /// Opens (and masks) every protected position of one DataRow.
    ///
    /// The two bounds in here are the reason this is not a straight loop.
    /// Decrypting one value allocates several times over its own size — the
    /// hex-decoded stored form, the opened plaintext, the masked copy, the hex
    /// re-encode — and every replacement stays live until the row is
    /// re-encoded at the end. Left unbounded, a single DataRow near the 1 GiB
    /// frame cap drives peak resident memory to several GiB *per session*,
    /// on top of the relay buffer already holding the frame (SEC-33). So:
    ///
    /// 1. [`Bounds::max_value`] caps each protected value, checked before any
    ///    copy of it is made;
    /// 2. [`Bounds::max_body`] caps the row's projected re-encoded size,
    ///    tracked as replacements are built, so an oversized row is refused
    ///    while it is being assembled rather than after — which is all
    ///    `session::encode_frame_header` can do, since it sees the finished
    ///    body.
    ///
    /// Both arrive as parameters rather than as constants: the first is the
    /// operator's `max_protected_value_bytes`, and the second is a constant in
    /// production (the largest body a frame header can express) but is passed
    /// so the bound stays testable without a gigabyte-sized fixture.
    fn decrypt_row(
        positions: &[(usize, ReadColumn, RowKeyRef)],
        formats: &ResultFormats,
        body: &[u8],
        bounds: Bounds,
    ) -> Result<Option<Vec<u8>>, Error> {
        // Before anything is read: an ambiguous row key refuses the whole
        // result set rather than being carried per value like an unreadable
        // one. Resolving it to the first match would open one instance of a
        // self-joined table against another instance's key, and nothing this
        // row carries can settle which instance a field came from (SEC-11).
        for (_, _, key) in positions {
            match key {
                RowKeyRef::Ambiguous { table, column } => {
                    return Err(Error::AmbiguousRowKey {
                        table: table.clone(),
                        column: column.clone(),
                    })
                }
                // Same class of problem, same up-front refusal: it is settled
                // by the description, so nothing this row carries could change
                // the answer and every row of the result set would repeat it.
                RowKeyRef::TypeChanged { table, column, wire, resolved } => {
                    return Err(Error::Wire(dbsec_core::Error::RowKeyType(format!(
                        "{table}.{column} came back as type oid {wire} but resolved as type oid \
                         {resolved}; re-resolve the proxy's columns, and re-encrypt the table if \
                         its key type really changed"
                    ))))
                }
                RowKeyRef::Absent | RowKeyRef::Slot { .. } => {}
            }
        }
        // Which protected columns came back at more than one position. Two
        // instances of a self-joined table share a `(table_oid, attnum)` and so
        // resolve to one `ReadColumn`, which makes this the only trace of the
        // shape that survives into the row — see [`Error::AmbiguousRowInstance`].
        // It is not a refusal on its own: `SELECT ssn, ssn FROM users` is the
        // same signal on one row, and it opens correctly.
        let repeated: HashSet<&str> = positions
            .iter()
            .map(|(_, column, _)| &*column.name)
            .fold((HashSet::new(), HashSet::new()), |(mut seen, mut twice), name| {
                if !seen.insert(name) {
                    twice.insert(name);
                }
                (seen, twice)
            })
            .1;
        let mut values: Vec<Option<Cow<'_, [u8]>>> =
            pgwire::parse_data_row(body)?.into_iter().map(|v| v.map(Cow::Borrowed)).collect();
        // `body` is exactly the encoding of `values`, so it is also the
        // starting point for what the rewritten row will encode to.
        let mut projected = body.len();
        let mut changed = false;
        // Read before the row is mutated: a row key is a plain column of the
        // same row, and sealing never rewrites it (config refuses a row key
        // that is itself protected), but taking it first keeps that
        // independent of ordering.
        //
        // The failure is *kept*, not discarded. Collapsing every unreadable
        // key to `None` made a NULL, a non-UTF-8 text key and a wrong-width
        // binary integer all surface as `RowKeyMissing`, whose refusal tells
        // the client to select the table's row key — which it already did
        // (ERR-7). It is carried rather than returned here because whether it
        // matters depends on the value it would have opened: an outer join's
        // unmatched row carries a NULL key *and* a NULL protected value, and
        // has nothing to bind.
        //
        // Canonicalised once per *distinct* slot, not once per protected
        // column: every protected column of one table shares that table's key,
        // so a table with `k` of them used to canonicalise the identical bytes
        // `k` times per row, each time through a fresh allocation. A row whose
        // positions carry no slot at all does not allocate here (PERF-3).
        let mut row_keys: Vec<RowKeyOnce> = distinct_slots(positions)
            .into_iter()
            .map(|(index, type_oid)| RowKeyOnce::read(index, type_oid, formats, &values))
            .collect();
        for (position, column, key) in positions {
            let Some(Some(value)) = values.get_mut(*position) else { continue };
            if value.len() > bounds.max_value {
                return Err(Error::ProtectedValueTooLarge {
                    position: *position,
                    len: value.len(),
                    max: bounds.max_value,
                });
            }
            let (replacement, hex_text) = {
                let (stored, hex_text) = match &column.transform {
                    Some(transform) => decode_wire(transform.as_ref(), value),
                    None => (Cow::Borrowed(&**value), false),
                };
                let opened = match &column.transform {
                    Some(transform) => {
                        let repeated = repeated.contains(&*column.name);
                        let attribute = |error, key| {
                            attribute_open_failure(error, column, *position, key, repeated)
                        };
                        let at = match key {
                            RowKeyRef::Slot { index, .. } => {
                                row_keys.iter().position(|once| once.index == *index)
                            }
                            // Both were refused before the row was read.
                            RowKeyRef::Absent
                            | RowKeyRef::Ambiguous { .. }
                            | RowKeyRef::TypeChanged { .. } => None,
                        };
                        match (at, at.and_then(|at| row_keys[at].key.as_ref())) {
                            (_, Some(key)) => transform
                                .open(&stored, Some(key))
                                .map_err(|e| attribute(e, Some(key)))?,
                            (None, None) => {
                                transform.open(&stored, None).map_err(|e| attribute(e, None))?
                            }
                            // The key could not be canonicalised. Whether that
                            // decides anything is the *stored value's* call:
                            // pre-migration plaintext and a `DBS2` value
                            // written before the table declared a key open
                            // without one and are unaffected, while a `DBS3`
                            // value reports `RowKeyMissing` — which would tell
                            // the client to select the row key it already
                            // selected. The real reason replaces it (ERR-7).
                            (Some(at), None) => match transform.open(&stored, None) {
                                Ok(opened) => opened,
                                Err(dbsec_core::Error::RowKeyMissing) => {
                                    return Err(row_keys[at].why.take().expect(
                                        "a slot that produced no key recorded why, and the row \
                                         is abandoned the first time that reason is taken",
                                    ))
                                }
                                Err(e) => return Err(attribute(e, None)),
                            },
                        }
                    }
                    None => None,
                };
                // Mask what the client would otherwise see: the opened
                // plaintext, or the raw value when nothing opened.
                let masked =
                    column.mask.map(|mask| mask.apply(opened.as_deref().unwrap_or(&stored)));
                (masked.or(opened), hex_text)
            };
            if let Some(replacement) = replacement {
                // A value that arrived hex-encoded goes back the same
                // way, or the client cannot decode the column.
                let replacement = if hex_text { hex_text_form(&replacement) } else { replacement };
                // Each position appears at most once in `positions`, so this
                // value's own length is still part of `projected` and the
                // subtraction cannot underflow.
                projected = projected - value.len() + replacement.len();
                if projected > bounds.max_body {
                    return Err(Error::FrameTooLarge {
                        msg_type: 'D',
                        body_len: projected,
                        max: bounds.max_body,
                    });
                }
                *value = Cow::Owned(replacement);
                changed = true;
            }
        }
        if !changed {
            return Ok(None);
        }
        Ok(Some(pgwire::encode_data_row(&values)?))
    }
}

/// The row-key slots of a described result set, deduplicated by the result
/// position they read from and in the order they first appear.
///
/// Every protected column of one table carries that table's slot, so a table
/// with `k` protected columns names the same position `k` times. Canonicalising
/// once per column meant canonicalising identical bytes `k` times per row, each
/// through its own allocation, on the proxy's hottest path (PERF-3). A join can
/// still contribute one slot per row-bound table, which is why this
/// deduplicates rather than assuming a single key.
///
/// Returns an empty `Vec` — which does not allocate — when no position carries
/// a slot at all, so a deployment that declares no row key pays nothing per
/// DataRow.
fn distinct_slots(positions: &[(usize, ReadColumn, RowKeyRef)]) -> Vec<(usize, u32)> {
    let mut slots: Vec<(usize, u32)> = Vec::new();
    for (_, _, key) in positions {
        if let RowKeyRef::Slot { index, type_oid } = key {
            if slots.iter().all(|(seen, _)| seen != index) {
                slots.push((*index, *type_oid));
            }
        }
    }
    slots
}

/// One distinct row-key slot of a result row, canonicalised once and then
/// shared by every protected column of that row that binds to it.
///
/// A `Result` split into its two halves rather than kept whole: the key is
/// *borrowed* by each column that opens against it, while the reason is *moved*
/// out by the one column that fails on it — the row is abandoned at that point,
/// so there is never a second taker.
struct RowKeyOnce {
    index: usize,
    key: Option<RowKey>,
    why: Option<Error>,
}

impl RowKeyOnce {
    fn read(
        index: usize,
        type_oid: u32,
        formats: &ResultFormats,
        values: &[Option<Cow<'_, [u8]>>],
    ) -> Self {
        match read_row_key(index, type_oid, formats, values) {
            Ok(key) => Self { index, key: Some(key), why: None },
            Err(why) => Self { index, key: None, why: Some(why) },
        }
    }
}

/// The canonical row key sitting at `index` of this result row, or why it could
/// not be derived.
///
/// Every failure keeps its own reason ([`dbsec_core::Error::RowKeyType`]) instead of
/// becoming an absent key: a key that is NULL, not valid UTF-8, the wrong width
/// for its type, or carried under an unknown format code is a *different*
/// problem from a query that never projected the key at all, and the refusal
/// the client gets has to say which one it is (ERR-7).
fn read_row_key(
    index: usize,
    type_oid: u32,
    formats: &ResultFormats,
    values: &[Option<Cow<'_, [u8]>>],
) -> Result<RowKey, Error> {
    // The description said the key is at this position, so a row too short to
    // hold it disagrees with the description it arrived under.
    let raw = values.get(index).ok_or_else(|| {
        dbsec_core::Error::RowKeyType(format!(
            "row key is described at result position {index} of a row carrying {} values",
            values.len()
        ))
    })?;
    // From the Bind, not from the description: a Describe of a statement
    // reports zero for every column, whatever the portal later asked for.
    let format = crate::portal::value_format(formats.for_column(index))?;
    Ok(dbsec_core::rowkey::canonical(type_oid, format, raw.as_deref())?)
}

/// Names the cell a failed `open` belongs to.
///
/// The row-bound case is what this exists for. A `DBS3` value that does not
/// authenticate against the row it came back in is the only externally visible
/// product of row binding, and until this it reached the relay as a bare
/// `Error::Decrypt` — logged as "transform failed; closing session" with the
/// direction and the frame type and nothing else, the identical line a key
/// rotation mishap or a stale column map produces (READ-8). Detection whose
/// alarm cannot be attributed is close to no detection.
///
/// Both added fields are non-secret: the qualified column name is
/// configuration, and the row key is a primary key the client itself selected
/// and that [`dbsec_core::envelope`] documents as not a secret. The plaintext
/// is not in reach here and never appears (SEC-21).
///
/// Nothing is logged here — the error is returned and the relay logs it once,
/// at the site that handles it (ERR-1).
fn attribute_open_failure(
    error: dbsec_core::Error,
    column: &ReadColumn,
    position: usize,
    row_key: Option<&RowKey>,
    repeated: bool,
) -> Error {
    match (&error, row_key) {
        // The self-join shape (SEC-11), which is only ever visible here: the
        // description resolved one key for this table and the same protected
        // column came back at several positions, so at most one of them can be
        // the instance that key names. Told apart from a genuine relocation by
        // nothing at all — hence one message that carries both readings.
        (dbsec_core::Error::Decrypt, Some(_)) if repeated => Error::AmbiguousRowInstance {
            table: table_of(&column.name).to_owned(),
            column: column.name.to_string(),
        },
        (dbsec_core::Error::Decrypt, Some(row_key)) => Error::RowBindingFailed {
            column: column.name.to_string(),
            row_key: String::from_utf8_lossy(row_key.as_bytes()).into_owned(),
            position,
        },
        _ => error.into(),
    }
}

/// The `schema.table` half of a configured column's qualified name.
///
/// Falls back to the whole name rather than panicking: it is only ever used in
/// a message, and a name without a dot would mean the resolver produced
/// something this path does not otherwise depend on.
fn table_of(qualified: &str) -> &str {
    qualified.rsplit_once('.').map_or(qualified, |(table, _)| table)
}

/// Decodes one column value's wire representation into its stored form.
/// BYTEA-form transforms see both: raw bytes (binary result format) and
/// `\x`-prefixed hex (text result format, e.g. the simple protocol);
/// text-form transforms (FPE, tokens) are the same bytes either way. The flag
/// reports the hex-text case, which the reply has to reproduce.
fn decode_wire<'a>(transform: &dyn FieldTransform, raw: &'a [u8]) -> (Cow<'a, [u8]>, bool) {
    match transform.wire() {
        WireForm::Bytea => match raw.strip_prefix(b"\\x").and_then(|h| hex::decode(h).ok()) {
            Some(decoded) => (Cow::Owned(decoded), true),
            None => (Cow::Borrowed(raw), false),
        },
        WireForm::Text => (Cow::Borrowed(raw), false),
    }
}

/// Re-encodes a replacement value into the `\x…` hex text a client that sent
/// the column that way expects to get back.
///
/// One allocation, deliberately. `format!("\\x{}", hex::encode(v))` builds the
/// hex twice — once as a `String` from `hex::encode`, once again as the
/// formatted `String` — so a value being decrypted was briefly resident four
/// times over. That multiplier is the whole read-path amplification problem
/// (SEC-33); writing straight into a right-sized buffer removes it.
fn hex_text_form(value: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 2 + value.len() * 2];
    out[..2].copy_from_slice(b"\\x");
    hex::encode_to_slice(value, &mut out[2..]).expect("the buffer is exactly twice the input");
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use dbsec_core::envelope::{self, Binding, CellContext, KeyId, KEY_ID_LEN};
    use dbsec_core::keys::{Key, KeySource};
    use dbsec_core::{blind_index, Error as CoreError};

    pub const KEY: [u8; 32] = [7u8; 32];
    pub const KEY_ID: KeyId = [1u8; KEY_ID_LEN];
    pub const INDEX_KEY: [u8; 32] = [3u8; 32];

    pub struct OneKey;

    impl KeySource for OneKey {
        fn active_key(&self) -> Result<(KeyId, Key), CoreError> {
            Ok((KEY_ID, Key::new(KEY)))
        }
        fn key(&self, id: &KeyId) -> Result<Key, CoreError> {
            if id == &KEY_ID {
                Ok(Key::new(KEY))
            } else {
                Err(CoreError::UnknownKey(hex::encode(id)))
            }
        }
        fn index_key(&self, _name: &str) -> Result<Key, CoreError> {
            Ok(Key::new(INDEX_KEY))
        }
    }

    /// The column every envelope in these tests is bound to — the one the
    /// fixture row description describes.
    pub fn cell_context() -> CellContext {
        CellContext::new("public.users.email")
    }

    /// A description of `count` protected columns at positions `0..count`, for
    /// the tests here and in [`crate::portal`] that only care how a
    /// description is routed rather than what it decrypts.
    pub fn description(count: usize) -> Positions {
        let fields: Vec<(u32, i16)> =
            (0..count).map(|attnum| (1234, i16::try_from(attnum).expect("small"))).collect();
        let columns: ColumnMap = fields
            .iter()
            .map(|key| {
                (
                    *key,
                    ReadColumn {
                        name: "public.users.email".into(),
                        transform: Some(transform(false)),
                        mask: None,
                    },
                )
            })
            .collect();
        let resolved = Resolved { columns, ..Default::default() };
        Arc::new(Described::new(
            &resolved,
            fields.into_iter().map(|(oid, attnum)| (oid, attnum, dbsec_core::rowkey::oid::TEXT)),
        ))
    }

    pub fn transform(searchable: bool) -> Arc<dyn FieldTransform> {
        transform_bound(searchable, false)
    }

    /// `strict` closes the column's row-binding migration window, as
    /// `strict_row_binding = true` on its `[[table]]` does in a real config.
    pub fn transform_bound(searchable: bool, strict: bool) -> Arc<dyn FieldTransform> {
        let index_key = searchable.then(|| "public.users.email".to_owned());
        let ciphers = Arc::new(envelope::Ciphers::new(Arc::new(OneKey)));
        Arc::new(
            dbsec_core::transform::EncryptTransform::new(ciphers, cell_context(), index_key)
                .strict_row_binding(strict),
        )
    }

    fn context_with(column: ReadColumn) -> Arc<RowContext> {
        let mut columns = ColumnMap::new();
        columns.insert((1234, 2), column);
        Arc::new(RowContext::new(
            Resolved { columns, names: HashSet::from(["email".to_owned()]), ..Default::default() },
            OnUnprotected::Warn,
            DEFAULT_MAX_PROTECTED_VALUE_LEN,
        ))
    }

    fn context(searchable: bool) -> Arc<RowContext> {
        context_with(ReadColumn {
            name: "public.users.email".into(),
            transform: Some(transform(searchable)),
            mask: None,
        })
    }

    fn row_description(fields: &[(u32, i16)]) -> Vec<u8> {
        let named: Vec<_> = fields.iter().map(|(oid, attnum)| ("", *oid, *attnum)).collect();
        named_row_description(&named)
    }

    /// A RowDescription that carries field labels, which is what the stale
    /// mapping check has to work from — the message names no table at all.
    fn named_row_description(fields: &[(&str, u32, i16)]) -> Vec<u8> {
        let mut body = (fields.len() as i16).to_be_bytes().to_vec();
        for (name, table_oid, attnum) in fields {
            body.extend_from_slice(name.as_bytes());
            body.push(0);
            body.extend_from_slice(&table_oid.to_be_bytes());
            body.extend_from_slice(&attnum.to_be_bytes());
            body.extend_from_slice(&[0u8; 12]);
        }
        body
    }

    /// The replacement body of a frame the decryptor rewrote, or `None` when
    /// it was relayed untouched. Tests that expect a refusal match on
    /// [`FrameAction::RefuseAndClose`] themselves.
    trait Rewritten {
        fn body(self) -> Option<Vec<u8>>;
    }

    impl Rewritten for FrameAction {
        fn body(self) -> Option<Vec<u8>> {
            match self {
                FrameAction::Relay => None,
                FrameAction::Replace(body) => Some(body),
                other => panic!("expected a relayed or rewritten frame, got {other:?}"),
            }
        }
    }

    fn data_row(values: &[Option<&[u8]>]) -> Vec<u8> {
        let cows: Vec<_> = values.iter().map(|v| v.map(Cow::Borrowed)).collect();
        pgwire::encode_data_row(&cows).unwrap()
    }

    /// Both directions of one session over the state they share, so a test
    /// can play a whole extended-protocol conversation.
    fn session(ctx: &Arc<RowContext>) -> (crate::encrypt::QueryRewriter, RowDecryptor) {
        use dbsec_core::policy::ProtectedColumn;
        let catalog = Arc::new(crate::encrypt::WriteCatalog::new(
            &[ProtectedColumn {
                schema: "public".into(),
                table: "users".into(),
                column: "email".into(),
                transform: Some(transform(false)),
                searchable: false,
                readable: true,
                mask: None,
            }],
            OnUnprotected::Warn,
        ));
        let portals = SessionPortals::new();
        let rewriter = crate::encrypt::QueryRewriter::new(
            catalog,
            portals.clone(),
            None,
            Arc::new(std::sync::atomic::AtomicU8::new(b'I')),
            crate::encrypt::StartupSettings::default(),
        );
        (rewriter, ctx.decryptor(portals))
    }

    /// A simple-protocol Query frame body.
    fn query_frame(sql: &str) -> Vec<u8> {
        let mut body = sql.as_bytes().to_vec();
        body.push(0);
        body
    }

    /// A session whose `users` table declares `id` as its row key, wired on
    /// both directions from one resolution — which is the point: the write path
    /// finds the key by name and the read path by OID, and they have to agree.
    ///
    /// `policy` reaches both catalogs, because every row-binding constraint is
    /// an [`OnUnprotected`] site: under `reject` the statement is refused, and
    /// under `warn` — the default a deployment actually runs on — it is
    /// relayed. A fixture hard-coded to `reject` can only ever test the half
    /// nobody is running.
    fn row_bound_session(
        policy: OnUnprotected,
    ) -> (Arc<RowContext>, crate::encrypt::QueryRewriter, RowDecryptor) {
        row_bound_session_strict(false, policy)
    }

    /// The same session with the table's row-binding migration window closed:
    /// a stored value carrying no row binding is then a downgrade, not an old
    /// value.
    fn row_bound_session_strict(
        strict: bool,
        policy: OnUnprotected,
    ) -> (Arc<RowContext>, crate::encrypt::QueryRewriter, RowDecryptor) {
        use dbsec_core::policy::ProtectedColumn;

        const TABLE: u32 = 1234;
        let tf = transform_bound(false, strict);
        let spec = ResolvedRowKey {
            attnum: 1,
            type_oid: dbsec_core::rowkey::oid::INT4,
            name: "id".into(),
            table: "public.users".into(),
        };
        let mut columns = ColumnMap::new();
        columns.insert(
            (TABLE, 2),
            ReadColumn {
                name: "public.users.email".into(),
                transform: Some(tf.clone()),
                mask: None,
            },
        );
        let ctx = Arc::new(RowContext::new(
            Resolved {
                columns,
                names: HashSet::from(["email".to_owned()]),
                row_keys: HashMap::from([(TABLE, spec.clone())]),
                row_key_by_table: HashMap::from([(
                    ("public".to_owned(), "users".to_owned()),
                    spec,
                )]),
                ..Default::default()
            },
            policy,
            DEFAULT_MAX_PROTECTED_VALUE_LEN,
        ));
        let catalog = Arc::new(crate::encrypt::WriteCatalog::new(
            &[ProtectedColumn {
                schema: "public".into(),
                table: "users".into(),
                column: "email".into(),
                transform: Some(tf),
                searchable: false,
                readable: true,
                mask: None,
            }],
            policy,
        ));
        let portals = SessionPortals::new();
        let rewriter = crate::encrypt::QueryRewriter::new(
            catalog,
            portals.clone(),
            Some(ctx.clone()),
            Arc::new(std::sync::atomic::AtomicU8::new(b'I')),
            crate::encrypt::StartupSettings::default(),
        );
        let decryptor = ctx.decryptor(portals);
        (ctx, rewriter, decryptor)
    }

    /// A RowDescription over the row-bound `users` fixture, from
    /// `(name, attnum, type_oid)` triples.
    ///
    /// Every field's format code is written as zero, which is what the server
    /// sends when a *statement* was described — and the read path takes the
    /// format from the Bind either way, so nothing here depends on it.
    fn described_fields(fields: &[(&[u8], i16, u32)]) -> Vec<u8> {
        let mut body = (fields.len() as i16).to_be_bytes().to_vec();
        for (name, attnum, type_oid) in fields {
            body.extend_from_slice(name);
            body.push(0);
            body.extend_from_slice(&1234u32.to_be_bytes());
            body.extend_from_slice(&attnum.to_be_bytes());
            body.extend_from_slice(&type_oid.to_be_bytes());
            body.extend_from_slice(&(-1i16).to_be_bytes());
            body.extend_from_slice(&(-1i32).to_be_bytes());
            body.extend_from_slice(&0i16.to_be_bytes());
        }
        body
    }

    /// The identities of `id` and `email` as the row key resolution expects
    /// them.
    const ROW_BOUND_ID: (&[u8], i16, u32) = (b"id", 1, dbsec_core::rowkey::oid::INT4);
    const ROW_BOUND_EMAIL: (&[u8], i16, u32) = (b"email", 2, dbsec_core::rowkey::oid::TEXT);

    /// A RowDescription for `SELECT id, email FROM users`.
    fn row_bound_description() -> Vec<u8> {
        described_fields(&[ROW_BOUND_ID, ROW_BOUND_EMAIL])
    }

    /// The finding, end to end: seal through the write path, read back through
    /// the read path, and prove the stored bytes do not open in another row.
    #[test]
    fn a_row_bound_value_does_not_open_in_another_row() {
        let (_ctx, mut rewriter, _decryptor) = row_bound_session(OnUnprotected::Reject);

        let sql = "INSERT INTO users (id, email) VALUES (7, 'alice@secret.test')";
        let rewritten = match rewriter.on_frame(b'Q', &query_frame(sql)).unwrap() {
            FrameAction::Replace(body) => String::from_utf8_lossy(&body).into_owned(),
            other => panic!("the insert must be rewritten, got {other:?}"),
        };
        assert!(!rewritten.contains("alice@secret.test"), "plaintext on the wire: {rewritten}");

        let start = rewritten.find("\\x").expect("sealed literal") + 2;
        let end = rewritten[start..].find('\'').unwrap() + start;
        let stored = hex::decode(&rewritten[start..end]).unwrap();
        assert!(stored.starts_with(envelope::MAGIC_V3), "the write is row-bound");

        // Read it back in its own row, on a fresh session: the write left a
        // pending Query response on the shared portal queue, and reusing it
        // here would test that interplay rather than the binding.
        let (_ctx, _r, mut decryptor) = row_bound_session(OnUnprotected::Reject);
        decryptor.on_frame(b'T', &row_bound_description()).unwrap();
        let own = data_row(&[Some(b"7"), Some(&stored)]);
        let opened = decryptor.on_frame(b'D', &own).unwrap().body().expect("rewritten");
        let values = pgwire::parse_data_row(&opened).unwrap();
        assert_eq!(values[1], Some(&b"alice@secret.test"[..]));

        // The same stored bytes pasted into another row. This fails the
        // session rather than answering the client, which is this module's
        // existing contract for a crypto failure and is right here: a value
        // that does not authenticate against the row it was read from is
        // tampering, not a query the client can fix by rewriting it.
        let (_ctx, _rewriter, mut decryptor) = row_bound_session(OnUnprotected::Reject);
        decryptor.on_frame(b'T', &row_bound_description()).unwrap();
        let moved = data_row(&[Some(b"8"), Some(&stored)]);
        let error = decryptor.on_frame(b'D', &moved).expect_err("a relocation must fail");
        // And it says which cell fired. The relay logs this error and nothing
        // else about the frame, so an alarm that reads only "decryption
        // failed" is one an operator cannot act on or tell apart from a key
        // rotation mishap.
        assert!(
            matches!(
                &error,
                Error::RowBindingFailed { column, row_key, position }
                    if column == "public.users.email" && row_key == "8" && *position == 1
            ),
            "a relocation must be attributed to its cell, got {error}"
        );
        let text = error.to_string();
        for part in ["public.users.email", "row key 8", "another row"] {
            assert!(text.contains(part), "the alarm must name {part}: {text}");
        }
    }

    /// The same failure with no row key in hand is *not* a relocation: an
    /// unknown key id or a cell-bound value opened under the wrong key stays
    /// the generic crypto failure, so the row-binding alarm means what it says.
    #[test]
    fn a_crypto_failure_with_no_row_key_is_not_reported_as_a_relocation() {
        let ctx = context(false);
        let mut decryptor = ctx.decryptor(SessionPortals::new());
        decryptor.on_frame(b'T', &row_description(&[(1234, 1), (1234, 2)])).unwrap();

        let ct =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), b"alice").unwrap();
        let mut tampered = ct.clone();
        *tampered.last_mut().expect("non-empty ciphertext") ^= 0xff;
        let row = data_row(&[Some(b"7"), Some(&tampered)]);
        assert!(
            matches!(decryptor.on_frame(b'D', &row), Err(Error::Wire(dbsec_core::Error::Decrypt))),
            "a cell-bound failure has no row to attribute the alarm to"
        );
    }

    /// Seals one value through the write path and hands back its stored bytes,
    /// which is the only way to get a genuinely row-bound `DBS3` value for the
    /// read path to fail against.
    fn sealed(sql: &str) -> Vec<u8> {
        let (_ctx, mut rewriter, _d) = row_bound_session(OnUnprotected::Reject);
        let rewritten = match rewriter.on_frame(b'Q', &query_frame(sql)).unwrap() {
            FrameAction::Replace(body) => String::from_utf8_lossy(&body).into_owned(),
            other => panic!("the insert must be rewritten, got {other:?}"),
        };
        let start = rewritten.find("\\x").expect("sealed literal") + 2;
        let end = rewritten[start..].find('\'').unwrap() + start;
        hex::decode(&rewritten[start..end]).expect("hex literal")
    }

    /// A literal key is normalised through its type before it is sealed, so
    /// every spelling PostgreSQL accepts on input binds to the one spelling it
    /// emits on output.
    ///
    /// `0007` used to seal against the literal `0007` while the row came back
    /// as `7`, and `-1` did not parse as a literal at all — it is
    /// `UnaryOp{Minus, Number}`, not a signed `Number` — so an ordinary
    /// negative key fell through to the missing-key gate (SEC-11).
    #[test]
    fn a_literal_row_key_binds_by_its_value_not_by_its_spelling() {
        for (literal, key) in [("0007", &b"7"[..]), ("+7", b"7"), ("-1", b"-1")] {
            let stored = sealed(&format!(
                "INSERT INTO users (id, email) VALUES ({literal}, 'alice@secret.test')"
            ));
            assert!(stored.starts_with(envelope::MAGIC_V3), "{literal} must seal row-bound");

            let (_ctx, _r, mut decryptor) = row_bound_session(OnUnprotected::Reject);
            decryptor.on_frame(b'T', &row_bound_description()).unwrap();
            let opened = decryptor
                .on_frame(b'D', &data_row(&[Some(key), Some(&stored)]))
                .unwrap_or_else(|e| panic!("{literal} must open in row {key:?}: {e}"))
                .body()
                .expect("rewritten");
            let values = pgwire::parse_data_row(&opened).unwrap();
            assert_eq!(values[1], Some(&b"alice@secret.test"[..]));
        }
    }

    /// The read path canonicalises through the type the *catalog* resolved,
    /// and refuses when the wire disagrees with it.
    ///
    /// `ALTER TABLE users ALTER COLUMN id TYPE …` is the case: the write path
    /// keeps canonicalising through the resolved type while `RowDescription`
    /// starts announcing the new one, so the two directions silently derive
    /// different keys and every value already stored stops opening. Refusing
    /// says which column moved instead (SEC-11).
    #[test]
    fn a_row_key_the_wire_types_differently_from_the_catalog_is_refused() {
        let stored = sealed("INSERT INTO users (id, email) VALUES (7, 'alice@secret.test')");

        let (_ctx, _r, mut decryptor) = row_bound_session(OnUnprotected::Reject);
        let retyped: (&[u8], i16, u32) = (b"id", 1, dbsec_core::rowkey::oid::UUID);
        decryptor.on_frame(b'T', &described_fields(&[retyped, ROW_BOUND_EMAIL])).unwrap();
        let frames =
            refused(decryptor.on_frame(b'D', &data_row(&[Some(b"7"), Some(&stored)])).unwrap());
        let text = String::from_utf8_lossy(&frames).into_owned();
        for part in ["users.id", "2950", "23"] {
            assert!(text.contains(part), "the refusal must name {part}: {text}");
        }

        // The matching description is unaffected: this is a disagreement
        // check, not a second type restriction.
        let (_ctx, _r, mut decryptor) = row_bound_session(OnUnprotected::Reject);
        decryptor.on_frame(b'T', &row_bound_description()).unwrap();
        decryptor
            .on_frame(b'D', &data_row(&[Some(b"7"), Some(&stored)]))
            .expect("the resolved type still opens")
            .body()
            .expect("rewritten");
    }

    /// Every protected column of a table shares that table's key, so the key is
    /// canonicalised once per row however many columns bind to it — and not at
    /// all when nothing does (PERF-3).
    #[test]
    fn one_row_key_is_canonicalised_once_however_many_columns_bind_to_it() {
        const TABLE: u32 = 1234;
        let spec = ResolvedRowKey {
            attnum: 1,
            type_oid: dbsec_core::rowkey::oid::INT4,
            name: "id".into(),
            table: "public.users".into(),
        };
        let mut columns = ColumnMap::new();
        for attnum in [2i16, 3] {
            columns.insert(
                (TABLE, attnum),
                ReadColumn {
                    name: format!("public.users.c{attnum}").into(),
                    transform: Some(transform(false)),
                    mask: None,
                },
            );
        }
        // SELECT id, c2, c3 FROM users
        let fields = [
            (TABLE, 1i16, dbsec_core::rowkey::oid::INT4),
            (TABLE, 2, dbsec_core::rowkey::oid::TEXT),
            (TABLE, 3, dbsec_core::rowkey::oid::TEXT),
        ];

        let bound = Resolved {
            columns: columns.clone(),
            row_keys: HashMap::from([(TABLE, spec)]),
            ..Default::default()
        };
        let positions = bound.protected(&fields);
        assert_eq!(positions.len(), 2, "both protected columns are found");
        let slots = distinct_slots(&positions);
        assert_eq!(slots.len(), 1, "two columns, one key, one canonicalisation");
        assert_eq!(slots[0].0, 0, "and it is the key's own result position");

        // A table with no declared key canonicalises nothing, so a deployment
        // that does not use the feature pays no per-row allocation for it.
        let unbound = Resolved { columns, ..Default::default() };
        assert!(distinct_slots(&unbound.protected(&fields)).is_empty());
    }

    /// A projected row key the proxy cannot canonicalise is refused *as that*.
    ///
    /// Discarding the error made every one of them — a NULL key, non-UTF-8
    /// text, a wrong-width binary integer, an unknown format code — arrive at
    /// the client as `RowKeyMissing`, whose refusal says to select the table's
    /// row key. The client selected it; the value in it is the problem, and a
    /// refusal that misdirects the fix is worse than one that says nothing.
    #[test]
    fn an_unusable_row_key_is_refused_as_itself_not_as_a_missing_projection() {
        let stored = sealed("INSERT INTO users (id, email) VALUES (7, 'alice@secret.test')");

        // The key column is projected, and NULL in this row.
        let (_ctx, _r, mut decryptor) = row_bound_session(OnUnprotected::Reject);
        decryptor.on_frame(b'T', &row_bound_description()).unwrap();
        let frames = refused(decryptor.on_frame(b'D', &data_row(&[None, Some(&stored)])).unwrap());
        let text = String::from_utf8_lossy(&frames);
        assert!(text.contains("42501"), "the client gets a SQLSTATE: {text}");
        assert!(text.contains("row key is NULL"), "the refusal must name the NULL: {text}");
        assert!(
            !text.contains("does not carry"),
            "and must not read as the missing-projection refusal: {text}"
        );

        // A wrong-width binary integer is the same class of failure and is
        // reported the same way, rather than being reinterpreted. It takes a
        // Bind to say the results come back in binary: the RowDescription of a
        // described *statement* reports zero for every column (SEC-31).
        let (_ctx, mut rewriter, mut decryptor) = row_bound_session(OnUnprotected::Reject);
        bind_results(&mut rewriter, &mut decryptor, 1);
        let short = data_row(&[Some(&[0, 0, 7]), Some(&stored)]);
        let text = String::from_utf8_lossy(&refused(decryptor.on_frame(b'D', &short).unwrap()))
            .into_owned();
        assert!(text.contains("expected 4"), "the refusal must name the width: {text}");

        // The projection the client really did omit still reports itself: this
        // is the refusal the case above used to be confused with.
        let (_ctx, _r, mut decryptor) = row_bound_session(OnUnprotected::Reject);
        decryptor.on_frame(b'T', &row_description(&[(1234, 2)])).unwrap();
        let text = String::from_utf8_lossy(&refused(
            decryptor.on_frame(b'D', &data_row(&[Some(&stored)])).unwrap(),
        ))
        .into_owned();
        assert!(text.contains("does not carry"), "a missing row key still says so: {text}");
    }

    /// A row key the proxy cannot read only refuses the values that need one.
    /// Pre-migration plaintext in the same column opens without a key and is
    /// unaffected — an outer join's unmatched row carries a NULL key, and
    /// nothing in it is row-bound.
    #[test]
    fn an_unusable_row_key_does_not_refuse_a_value_that_needs_no_key() {
        let (_ctx, _r, mut decryptor) = row_bound_session(OnUnprotected::Reject);
        decryptor.on_frame(b'T', &row_bound_description()).unwrap();
        let plaintext = data_row(&[None, Some(b"not-an-envelope")]);
        assert!(
            decryptor.on_frame(b'D', &plaintext).unwrap().body().is_none(),
            "a value that opens without a row key must not be refused by the key it never used"
        );
    }

    /// What `strict_row_binding` buys, from the client's side. A cell-only
    /// value in a row-bound column is what every write-path degradation leaves
    /// behind — an upsert branch, an `UPDATE` that could not name one row — and
    /// while the migration window is open it opens like any pre-`row_key`
    /// value, so the degradation is invisible. Closed, the same bytes are
    /// refused with a reason the operator can act on.
    #[test]
    fn a_value_with_no_row_binding_is_refused_once_the_migration_window_closes() {
        let degraded =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), b"alice@secret.test")
                .unwrap();
        let row = data_row(&[Some(b"7"), Some(&degraded)]);

        // Window open: it opens, and the projected row key binds nothing.
        let (_ctx, _r, mut decryptor) = row_bound_session_strict(false, OnUnprotected::Reject);
        decryptor.on_frame(b'T', &row_bound_description()).unwrap();
        let opened = decryptor.on_frame(b'D', &row).unwrap().body().expect("rewritten");
        assert_eq!(pgwire::parse_data_row(&opened).unwrap()[1], Some(&b"alice@secret.test"[..]));

        // Window closed: the client is answered rather than the session merely
        // failing, because the remedy — re-encrypt the value, or reopen the
        // window — is the operator's and the reason has to reach them.
        let (_ctx, _r, mut decryptor) = row_bound_session_strict(true, OnUnprotected::Reject);
        decryptor.on_frame(b'T', &row_bound_description()).unwrap();
        let frames = refused(decryptor.on_frame(b'D', &row).unwrap());
        let text = String::from_utf8_lossy(&frames);
        assert!(text.contains("42501"), "the client gets a SQLSTATE: {text}");
        assert!(text.contains("strict_row_binding"), "and the setting to act on: {text}");
    }

    /// A Bind result-format section asking for every column in `format`.
    fn result_formats(format: i16) -> Vec<u8> {
        let mut section = 1i16.to_be_bytes().to_vec();
        section.extend_from_slice(&format.to_be_bytes());
        section
    }

    /// Plays `SELECT id, email FROM users` through both directions as a driver
    /// with a prepared-statement cache sends it — Parse, Describe(statement),
    /// Bind asking for `format` results, Execute, Sync — and answers the
    /// Describe with the RowDescription the server would send, whose format
    /// codes the protocol pins at zero.
    ///
    /// Leaves the decryptor with that Execute in flight, so the next DataRow
    /// is decrypted against the portal.
    fn bind_results(
        rewriter: &mut crate::encrypt::QueryRewriter,
        decryptor: &mut RowDecryptor,
        format: i16,
    ) {
        prepare(rewriter, b"s1", b"SELECT id, email FROM users");
        rewriter
            .on_frame(
                b'B',
                &pgwire::encode_bind(b"", b"s1", &[], &[], &result_formats(format)).unwrap(),
            )
            .unwrap();
        rewriter.on_frame(b'E', b"\0\0\0\0\0").unwrap();
        rewriter.on_frame(b'S', b"").unwrap();
        decryptor.on_frame(b'T', &row_bound_description()).unwrap();
        decryptor.on_frame(b'Z', b"I").unwrap();
    }

    /// A row written through a text-binding client, read back through a
    /// binary-binding one — the shape sqlx and every other binary driver
    /// produces.
    ///
    /// The wire format of the row key cannot come from the RowDescription
    /// here: the client described the *statement*, and the protocol specifies
    /// that a statement's format codes "will always be zero" because result
    /// formats are chosen at Bind. Taking them from the description read the
    /// four big-endian bytes of `7` as the text row key `\0\0\0\a`, which
    /// mismatched the AAD and tore the session down with `Error::Decrypt` —
    /// on the ordinary traffic of a whole class of drivers (SEC-31).
    #[test]
    fn a_row_bound_value_opens_in_the_format_the_bind_asked_for() {
        let stored = sealed("INSERT INTO users (id, email) VALUES (7, 'alice@x.io')");

        for (format, key) in [(1i16, 7i32.to_be_bytes().to_vec()), (0, b"7".to_vec())] {
            let (_ctx, mut rewriter, mut decryptor) = row_bound_session(OnUnprotected::Reject);
            bind_results(&mut rewriter, &mut decryptor, format);
            let row = data_row(&[Some(&key), Some(&stored)]);
            let opened = decryptor.on_frame(b'D', &row).unwrap().body().expect("rewritten");
            assert_eq!(
                pgwire::parse_data_row(&opened).unwrap()[1],
                Some(&b"alice@x.io"[..]),
                "result format {format} must open the row it was written in"
            );
        }
    }

    /// A self-join projects one table's row key twice, and RowDescription
    /// carries nothing that tells `a.id` from `b.id`: both instances of the
    /// relation report the same `(table_oid, attnum)`.
    ///
    /// Resolving to the first match gave `b.email` `a.id`'s key, so it failed
    /// to open as `Error::Decrypt` — the signal a *relocated* value produces —
    /// on ordinary SQL, which is exactly what makes a detection control stop
    /// being read as one. The ambiguity is named to the client instead
    /// (SEC-11).
    #[test]
    fn a_self_join_projecting_the_row_key_twice_is_refused_by_name() {
        let (ctx, _r, mut decryptor) = row_bound_session(OnUnprotected::Reject);
        // `SELECT a.id, a.email, b.id, b.email FROM users a JOIN users b …`.
        let description = [ROW_BOUND_ID, ROW_BOUND_EMAIL, ROW_BOUND_ID, ROW_BOUND_EMAIL];

        // Straight through `Described::new` and `decrypt_row`: the ambiguity
        // is recorded when the description is resolved and refused when a row
        // needs the key.
        let described = Described::new(
            &ctx.resolved(),
            description.iter().map(|(_, attnum, type_oid)| (1234, *attnum, *type_oid)),
        );
        let stored = sealed("INSERT INTO users (id, email) VALUES (7, 'alice@x.io')");
        let row = data_row(&[Some(b"7"), Some(&stored), Some(b"8"), Some(&stored)]);
        let refused = RowDecryptor::decrypt_row(
            described.columns(),
            &ResultFormats::default(),
            &row,
            Bounds {
                max_value: DEFAULT_MAX_PROTECTED_VALUE_LEN,
                max_body: pgwire::MAX_MESSAGE_LEN - 4,
            },
        );
        assert!(
            matches!(refused, Err(Error::AmbiguousRowKey { .. })),
            "a doubly projected row key must not resolve to the first match: {refused:?}"
        );

        // And on the session it is a refusal the client is told about, not a
        // crypto failure that only closes the socket.
        decryptor.on_frame(b'T', &described_fields(&description)).unwrap();
        let FrameAction::RefuseAndClose(body) = decryptor.on_frame(b'D', &row).unwrap() else {
            panic!("a self-join over a row-keyed table must be refused, not relayed")
        };
        let message = String::from_utf8_lossy(&body);
        assert!(message.contains("public.users.id"), "the refusal must name the key: {message}");
    }

    /// The complement of the shape above, and the harder half: a self-join that
    /// projects the row key **once** — `SELECT a.id, a.email, b.email FROM
    /// users a JOIN users b …`. The description resolves cleanly, so nothing is
    /// refused up front, and `b.email` is then opened against `a.id`'s key.
    ///
    /// RowDescription cannot separate this from `SELECT id, email, email FROM
    /// users`, where both fields genuinely name the same row: the two produce
    /// *byte-identical* descriptions, which is why the pair below is asserted
    /// against one `description`. So the shape is not refused on sight — the
    /// value is opened, and only a failure to authenticate, on a column that
    /// came back more than once, distinguishes them. Refusing on the
    /// description alone would have broken the legitimate query (SEC-11).
    #[test]
    fn a_self_join_projecting_the_row_key_once_is_refused_when_a_value_belongs_elsewhere() {
        // `SELECT a.id, a.email, b.email FROM users a JOIN users b …` — and
        // also `SELECT id, email, email FROM users`. Same three fields.
        let description = [ROW_BOUND_ID, ROW_BOUND_EMAIL, ROW_BOUND_EMAIL];
        let row_seven = sealed("INSERT INTO users (id, email) VALUES (7, 'alice@x.io')");
        let row_eight = sealed("INSERT INTO users (id, email) VALUES (8, 'bob@x.io')");

        // The self-join: the third field is row 8's value, read under row 7's
        // key. It cannot open, and the client is told what to do about it.
        let (_ctx, _r, mut decryptor) = row_bound_session(OnUnprotected::Reject);
        decryptor.on_frame(b'T', &described_fields(&description)).unwrap();
        let row = data_row(&[Some(b"7"), Some(&row_seven), Some(&row_eight)]);
        let FrameAction::RefuseAndClose(body) = decryptor.on_frame(b'D', &row).unwrap() else {
            panic!("a value that cannot belong to the projected row must not be relayed")
        };
        let message = String::from_utf8_lossy(&body);
        assert!(message.contains("42501"), "the client gets a SQLSTATE: {message}");
        assert!(message.contains("public.users"), "the refusal must name the table: {message}");
        assert!(message.contains("separately"), "and say how to fix it: {message}");
        assert!(!message.contains("bob@x.io"), "and never the plaintext: {message}");

        // AC#2: the same description, both values genuinely row 7's. Nothing
        // about the repetition is a refusal on its own.
        let (_ctx, _r, mut decryptor) = row_bound_session(OnUnprotected::Reject);
        decryptor.on_frame(b'T', &described_fields(&description)).unwrap();
        let row = data_row(&[Some(b"7"), Some(&row_seven), Some(&row_seven)]);
        let opened = decryptor.on_frame(b'D', &row).unwrap().body().expect("rewritten");
        let values = pgwire::parse_data_row(&opened).unwrap();
        assert_eq!(values[1], Some(&b"alice@x.io"[..]), "the first instance opens");
        assert_eq!(values[2], Some(&b"alice@x.io"[..]), "and so does the repeat");
    }

    /// The sealed literals of a rewritten statement, in the order they appear.
    fn sealed_literals(sql: &str) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut rest = sql;
        while let Some(start) = rest.find("\\x") {
            let tail = &rest[start + 2..];
            let end = tail.find('\'').expect("terminated literal");
            out.push(hex::decode(&tail[..end]).expect("hex literal"));
            rest = &tail[end..];
        }
        out
    }

    /// The rewritten SQL of a simple-protocol statement, or the refusal text.
    fn write(rewriter: &mut crate::encrypt::QueryRewriter, sql: &str) -> Result<String, String> {
        match rewriter.on_frame(b'Q', &query_frame(sql)).unwrap() {
            FrameAction::Replace(body) => Ok(String::from_utf8_lossy(&body).into_owned()),
            FrameAction::Relay => Ok(sql.to_owned()),
            FrameAction::Reply(bytes) | FrameAction::RefuseAndClose(bytes) => {
                Err(String::from_utf8_lossy(&bytes).into_owned())
            }
        }
    }

    /// The row key a `users` row with this `id` is sealed against.
    fn key_of(id: &str) -> RowKey {
        dbsec_core::rowkey::canonical(
            dbsec_core::rowkey::oid::INT4,
            dbsec_core::rowkey::Format::Text,
            Some(id.as_bytes()),
        )
        .expect("canonical row key")
    }

    /// `INSERT … ON CONFLICT (id) DO UPDATE SET email = …` built the conflict
    /// action's scope with a hardcoded `RowKeySource::None`, so the same
    /// statement wrote `DBS3` for the inserted row and a relocatable `DBS2`
    /// for the conflict-updated one — with no site reported, so `reject` did
    /// not catch it either.
    #[test]
    fn an_upsert_binds_its_conflict_action_to_the_row_it_conflicts_on() {
        let (_ctx, mut rewriter, _d) = row_bound_session(OnUnprotected::Reject);
        let rewritten = write(
            &mut rewriter,
            "INSERT INTO users (id, email) VALUES (7, 'alice@x.io') \
             ON CONFLICT (id) DO UPDATE SET email = 'bob@x.io'",
        )
        .expect("the upsert conflicts on the row key, so both values bind to it");

        let sealed = sealed_literals(&rewritten);
        assert_eq!(sealed.len(), 2, "both the value and the conflict action are sealed");
        for stored in &sealed {
            assert!(stored.starts_with(envelope::MAGIC_V3), "row-bound: {stored:?}");
        }
        let key = key_of("7");
        assert_eq!(
            transform(false).open(&sealed[1], Some(&key)).unwrap(),
            Some(b"bob@x.io".to_vec()),
            "the conflict action is bound to the row ON CONFLICT (id) names"
        );
    }

    /// Every conflict action whose row key the statement does not pin: a
    /// conflict on another unique column, a named constraint, MySQL's
    /// `ON DUPLICATE KEY UPDATE`, and a multi-row `VALUES` list — each of
    /// which updates a row that may carry any key at all.
    #[test]
    fn an_upsert_that_cannot_name_its_conflicting_row_is_refused() {
        for sql in [
            "INSERT INTO users (id, email) VALUES (7, 'a@x.io') \
             ON CONFLICT (email) DO UPDATE SET email = 'b@x.io'",
            "INSERT INTO users (id, email) VALUES (7, 'a@x.io') \
             ON CONFLICT ON CONSTRAINT users_pkey DO UPDATE SET email = 'b@x.io'",
            "INSERT INTO users (id, email) VALUES (7, 'a@x.io') \
             ON DUPLICATE KEY UPDATE email = 'b@x.io'",
            "INSERT INTO users (id, email) VALUES (7, 'a@x.io'), (8, 'c@x.io') \
             ON CONFLICT (id) DO UPDATE SET email = 'b@x.io'",
        ] {
            let (_ctx, mut rewriter, _d) = row_bound_session(OnUnprotected::Reject);
            let refusal = write(&mut rewriter, sql).expect_err(sql);
            assert!(refusal.contains("row key id"), "{sql} => {refusal}");
        }
    }

    /// `SET email = EXCLUDED.email` re-stores the value sealed for the
    /// *inserted* row, which is the right ciphertext for the conflicting row
    /// only when the two share a key — so it stays passed through on
    /// `ON CONFLICT (id)` and is refused on any other target.
    #[test]
    fn excluded_is_re_stored_only_where_the_conflicting_row_shares_the_key() {
        let (_ctx, mut rewriter, _d) = row_bound_session(OnUnprotected::Reject);
        let rewritten = write(
            &mut rewriter,
            "INSERT INTO users (id, email) VALUES (7, 'alice@x.io') \
             ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email",
        )
        .expect("re-storing the sealed value is what the column is supposed to hold");
        assert!(rewritten.contains("EXCLUDED.email"), "{rewritten}");
        assert_eq!(sealed_literals(&rewritten).len(), 1, "only the VALUES row is sealed");

        let (_ctx, mut rewriter, _d) = row_bound_session(OnUnprotected::Reject);
        let refusal = write(
            &mut rewriter,
            "INSERT INTO users (id, email) VALUES (7, 'alice@x.io') \
             ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email",
        )
        .expect_err("the conflicting row's key is not the one EXCLUDED.email is sealed against");
        assert!(refusal.contains("row key id"), "{refusal}");
    }

    /// `row_key_in_predicate` matched on the *last* ident of a compound name,
    /// so `UPDATE … FROM` bound the value to the joined relation's key: the
    /// `a.id = 1` arm won over `u.id = 99` and the value was sealed against a
    /// row the statement never writes. Attacker-influenceable, because the
    /// joined relation and its predicate are the free part of the statement.
    #[test]
    fn an_update_from_binds_the_target_relations_row_key_not_the_joined_ones() {
        let (_ctx, mut rewriter, _d) = row_bound_session(OnUnprotected::Reject);
        let rewritten = write(
            &mut rewriter,
            "UPDATE users u SET email = 'alice@x.io' FROM audit a WHERE a.id = 1 AND u.id = 99",
        )
        .expect("u.id pins the row this statement writes");

        let sealed = sealed_literals(&rewritten);
        assert_eq!(sealed.len(), 1);
        assert_eq!(
            transform(false).open(&sealed[0], Some(&key_of("99"))).unwrap(),
            Some(b"alice@x.io".to_vec()),
            "bound to the row the UPDATE writes"
        );
        assert!(
            transform(false).open(&sealed[0], Some(&key_of("1"))).is_err(),
            "never bound to the joined relation's key"
        );
    }

    /// The same statement with the target's key left unqualified: with a join
    /// in scope a bare `id` may belong to either relation, and the catalog
    /// holds no columns for the unprotected one, so it is signalled rather
    /// than guessed.
    #[test]
    fn an_unqualified_row_key_is_refused_once_the_statement_joins() {
        let (_ctx, mut rewriter, _d) = row_bound_session(OnUnprotected::Reject);
        let refusal = write(
            &mut rewriter,
            "UPDATE users u SET email = 'alice@x.io' FROM audit a WHERE a.id = 1 AND id = 99",
        )
        .expect_err("a bare id is ambiguous across the join");
        assert!(refusal.contains("row key id"), "{refusal}");
    }

    /// An assignment list that writes the row key moves the row out from under
    /// the key its `WHERE` pins, so a value sealed against that key lands in a
    /// row that can never open it. Both assignment-target shapes are covered.
    #[test]
    fn an_update_that_also_assigns_the_row_key_is_refused() {
        for sql in [
            "UPDATE users SET email = 'a@x.io', id = 99 WHERE id = 7",
            "UPDATE users SET (id, email) = (99, 'a@x.io') WHERE id = 7",
            "INSERT INTO users (id, email) VALUES (7, 'a@x.io') \
             ON CONFLICT (id) DO UPDATE SET email = 'b@x.io', id = 99",
        ] {
            let (_ctx, mut rewriter, _d) = row_bound_session(OnUnprotected::Reject);
            let refusal = write(&mut rewriter, sql).expect_err(sql);
            assert!(refusal.contains("assigns id itself"), "{sql} => {refusal}");
        }
    }

    /// Every write-path site that cannot say which row a statement writes,
    /// under **both** settings of `on_unprotected`.
    ///
    /// All three route through [`crate::encrypt::Unprotected::RowKeyMissing`],
    /// so `warn` — the default — relays the statement rather than refusing it.
    /// None of them had a test at all, in either mode: a refactor that dropped
    /// the row-key checks would have turned every row-bound `INSERT` into a
    /// plaintext write with the suite still green.
    ///
    /// All three seal **cell-only** under `warn` — the binding the table had
    /// before it declared a row key. The two `INSERT` sites used to relay the
    /// statement unsealed, which turned a relocatable ciphertext into plaintext
    /// at rest and made adopting `row_key` a downgrade; TASK-0184 gave them the
    /// assignment site's fallback. That every site agrees is the property under
    /// test, so a path that fails open again fails here.
    #[test]
    fn every_site_that_cannot_name_the_row_reports_itself_in_both_modes() {
        // (sql, the shape the site reports)
        const SITES: [(&str, &str); 3] = [
            (
                "INSERT INTO users (email) VALUES ('alice@secret.test')",
                "INSERT without the row key in its column list",
            ),
            (
                "INSERT INTO users (id, email) VALUES (nextval('users_id_seq'), \
                 'alice@secret.test')",
                "INSERT whose row key is not a literal or a parameter",
            ),
            (
                "UPDATE users SET email = 'alice@secret.test' WHERE dept = 'x'",
                "UPDATE whose WHERE does not pin one row by its row key",
            ),
        ];

        for (sql, shape) in SITES {
            let (_ctx, mut rewriter, _d) = row_bound_session(OnUnprotected::Reject);
            let refusal = write(&mut rewriter, sql).expect_err(sql);
            assert!(refusal.contains("public.users"), "{sql} => {refusal}");
            assert!(refusal.contains("row key id"), "{sql} => {refusal}");
            assert!(refusal.contains(shape), "{sql} => {refusal}");
            assert!(!refusal.contains("alice@secret.test"), "{sql} => {refusal}");
        }

        let (relayed, events) = crate::captured_events(|| {
            SITES
                .iter()
                .map(|(sql, _)| {
                    let (_ctx, mut rewriter, _d) = row_bound_session(OnUnprotected::Warn);
                    write(&mut rewriter, sql).expect("warn relays rather than refusing")
                })
                .collect::<Vec<_>>()
        });

        assert_eq!(events.len(), SITES.len(), "one warning per site: {events:?}");
        for (event, (sql, shape)) in events.iter().zip(SITES) {
            assert!(event.contains("public.users"), "{sql} => {event}");
            assert!(event.contains("row_key=id"), "{sql} => {event}");
            assert!(event.contains(shape), "{sql} => {event}");
            assert!(!event.contains("alice@secret.test"), "the warning must not log it: {event}");
        }
        for (rewritten, (sql, _)) in relayed.iter().zip(SITES) {
            let sealed = sealed_literals(rewritten);
            assert_eq!(sealed.len(), 1, "{sql} => {rewritten}");
            assert!(
                sealed[0].starts_with(envelope::MAGIC),
                "cell-only, never plaintext and never row-bound: {sql}"
            );
            assert!(!rewritten.contains("alice@secret.test"), "{sql} => {rewritten}");
        }
    }

    /// The read-path counterpart: a result set that omits the row key cannot
    /// verify a row-bound value, so it is refused rather than relayed in its
    /// stored form. `row_bound_description` always projects both fields, so no
    /// test produced this shape.
    #[test]
    fn a_result_set_without_the_row_key_refuses_a_row_bound_value() {
        let stored = sealed("INSERT INTO users (id, email) VALUES (7, 'alice@secret.test')");
        assert!(stored.starts_with(envelope::MAGIC_V3), "the fixture value is row-bound");

        let (_ctx, _r, mut decryptor) = row_bound_session(OnUnprotected::Reject);
        // `SELECT email FROM users`: the same table, without its key column.
        decryptor.on_frame(b'T', &row_description(&[(1234, 2)])).unwrap();
        let frames = refused(decryptor.on_frame(b'D', &data_row(&[Some(&stored)])).unwrap());
        let text = String::from_utf8_lossy(&frames);
        assert!(text.contains("42501"), "the client gets a SQLSTATE: {text}");
        assert!(text.contains("does not carry"), "and is told what to select: {text}");
        assert!(!text.contains("alice@secret.test"), "and never the plaintext: {text}");
    }

    /// Parse `sql`, then Bind `params` to it, and hand back what the proxy did
    /// with the Bind. The row key of a bound statement only exists at Bind, so
    /// nothing about it can be exercised through the simple protocol.
    fn bind_params(
        rewriter: &mut crate::encrypt::QueryRewriter,
        sql: &str,
        formats: &[i16],
        params: &[Option<&[u8]>],
    ) -> FrameAction {
        rewriter
            .on_frame(b'P', &pgwire::encode_parse(b"s", sql.as_bytes(), &0i16.to_be_bytes()))
            .expect("the statement parses");
        let params: Vec<Option<Cow<'_, [u8]>>> =
            params.iter().map(|p| p.map(Cow::Borrowed)).collect();
        let bind = pgwire::encode_bind(b"", b"s", formats, &params, &0i16.to_be_bytes())
            .expect("the bind encodes");
        rewriter.on_frame(b'B', &bind).expect("a bad row key must not fail the session")
    }

    /// A row key bound as a parameter is *client input*, and every way it can
    /// be unusable — NULL, non-UTF-8 text, a wrong-width binary integer, an
    /// undefined format code — used to propagate as an `Error` out of Bind,
    /// which closed the connection with no ErrorResponse at all. `UPDATE users
    /// SET email = $1 WHERE id = $2` with `$2` NULL is ordinary traffic, and
    /// under a connection pool the retry took the next connection down too.
    #[test]
    fn an_unusable_row_key_parameter_refuses_the_statement_not_the_session() {
        const SQL: &str = "UPDATE users SET email = $1 WHERE id = $2";
        let email = b"alice@secret.test".as_slice();

        for (formats, params, expected) in [
            (&[][..], vec![Some(email), None], "row key is NULL"),
            (&[0, 1][..], vec![Some(email), Some(&[0, 0, 7][..])], "expected 4"),
            (&[0, 7][..], vec![Some(email), Some(b"7".as_slice())], "unknown wire format code 7"),
        ] {
            let (_ctx, mut rewriter, _d) = row_bound_session(OnUnprotected::Reject);
            let refusal = match bind_params(&mut rewriter, SQL, formats, &params) {
                FrameAction::Reply(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                other => panic!("a bad row key must be refused, got {other:?}"),
            };
            assert!(refusal.contains("42501"), "the client gets a SQLSTATE: {refusal}");
            assert!(refusal.contains("$2"), "the refusal must name the placeholder: {refusal}");
            assert!(refusal.contains("row key id"), "and the row-key column: {refusal}");
            assert!(refusal.contains(expected), "and why it is unusable: {refusal}");
            assert!(
                !refusal.contains("alice@secret.test"),
                "the sealed value must not reach the client: {refusal}"
            );

            // And the session is still the client's to use: the rest of the
            // batch is swallowed, Sync answers ReadyForQuery, and the next
            // statement seals as if nothing had happened.
            assert!(
                matches!(rewriter.on_frame(b'E', b"\0\0\0\0\0").unwrap(), FrameAction::Reply(rest)
                    if rest.is_empty()),
                "the refused batch is owned by the proxy until Sync"
            );
            match rewriter.on_frame(b'S', b"").unwrap() {
                FrameAction::Reply(ready) => assert_eq!(ready.first(), Some(&b'Z'), "{ready:?}"),
                other => panic!("Sync must answer ReadyForQuery, got {other:?}"),
            }
            let rewritten =
                write(&mut rewriter, "INSERT INTO users (id, email) VALUES (7, 'bob@x.io')")
                    .expect("the session survived the refusal");
            assert_eq!(
                sealed_literals(&rewritten).len(),
                1,
                "the next statement still seals: {rewritten}"
            );
        }
    }

    /// Parse + Describe(statement) + Sync: what a driver sends the first time
    /// it sees a query.
    fn prepare(rewriter: &mut crate::encrypt::QueryRewriter, statement: &[u8], sql: &[u8]) {
        rewriter
            .on_frame(b'P', &pgwire::encode_parse(statement, sql, &0i16.to_be_bytes()))
            .unwrap();
        let mut describe = vec![b'S'];
        describe.extend_from_slice(statement);
        describe.push(0);
        rewriter.on_frame(b'D', &describe).unwrap();
        rewriter.on_frame(b'S', b"").unwrap();
    }

    /// Bind + Execute + Sync: what the same driver sends on every later call,
    /// once the statement is in its cache. No Describe, so no RowDescription.
    fn execute(rewriter: &mut crate::encrypt::QueryRewriter, statement: &[u8]) {
        rewriter
            .on_frame(
                b'B',
                &pgwire::encode_bind(b"", statement, &[], &[], &0i16.to_be_bytes()).unwrap(),
            )
            .unwrap();
        rewriter.on_frame(b'E', b"\0\0\0\0\0").unwrap();
        rewriter.on_frame(b'S', b"").unwrap();
    }

    /// A statement's result set, from the server's side.
    fn complete(decryptor: &mut RowDecryptor) {
        decryptor.on_frame(b'C', b"SELECT 1\0").unwrap();
        decryptor.on_frame(b'Z', b"I").unwrap();
    }

    #[test]
    fn decrypts_matched_columns_and_passes_others_through() {
        let ctx = context(false);
        let mut decryptor = ctx.decryptor(SessionPortals::new());

        let desc = row_description(&[(1234, 1), (1234, 2)]);
        assert!(decryptor.on_frame(b'T', &desc).unwrap().body().is_none());

        let ct =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), b"alice@example.com")
                .unwrap();
        let row = data_row(&[Some(b"42"), Some(&ct)]);
        let rewritten = decryptor.on_frame(b'D', &row).unwrap().body().unwrap();
        assert_eq!(
            pgwire::parse_data_row(&rewritten).unwrap(),
            vec![Some(b"42".as_slice()), Some(b"alice@example.com".as_slice())]
        );

        // Text-format (hex) representation decrypts too, and goes back in the
        // same shape — a client decoding BYTEA text expects `\x` hex.
        let hex_row = data_row(&[Some(b"42"), Some(format!("\\x{}", hex::encode(&ct)).as_bytes())]);
        let rewritten = decryptor.on_frame(b'D', &hex_row).unwrap().body().unwrap();
        assert_eq!(
            pgwire::parse_data_row(&rewritten).unwrap()[1],
            Some(format!("\\x{}", hex::encode("alice@example.com")).as_bytes())
        );

        // Plaintext (pre-migration) and NULL pass through untouched.
        let plain_row = data_row(&[Some(b"42"), Some(b"not encrypted")]);
        assert!(decryptor.on_frame(b'D', &plain_row).unwrap().body().is_none());
        let null_row = data_row(&[Some(b"42"), None]);
        assert!(decryptor.on_frame(b'D', &null_row).unwrap().body().is_none());
    }

    #[test]
    fn searchable_columns_lose_their_blind_index() {
        let ctx = context(true);
        let mut decryptor = ctx.decryptor(SessionPortals::new());
        decryptor.on_frame(b'T', &row_description(&[(1234, 1), (1234, 2)])).unwrap();

        let ct =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), b"alice").unwrap();
        let index = blind_index::compute(&INDEX_KEY, b"alice");
        let stored = blind_index::prepend(&index, &ct);
        let row = data_row(&[Some(b"42"), Some(&stored)]);
        let rewritten = decryptor.on_frame(b'D', &row).unwrap().body().unwrap();
        assert_eq!(pgwire::parse_data_row(&rewritten).unwrap()[1], Some(b"alice".as_slice()));
    }

    #[test]
    fn unmatched_result_sets_relay_untouched() {
        let ctx = context(false);
        let mut decryptor = ctx.decryptor(SessionPortals::new());
        decryptor.on_frame(b'T', &row_description(&[(9999, 1)])).unwrap();

        let ct =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), b"secret").unwrap();
        let row = data_row(&[Some(&ct)]);
        assert!(decryptor.on_frame(b'D', &row).unwrap().body().is_none());
    }

    #[test]
    fn unknown_key_fails_closed() {
        let ctx = context(false);
        let mut decryptor = ctx.decryptor(SessionPortals::new());
        decryptor.on_frame(b'T', &row_description(&[(1234, 2)])).unwrap();

        let ct =
            envelope::encrypt(&KEY, &[9u8; KEY_ID_LEN], &Binding::cell(&cell_context()), b"secret")
                .unwrap();
        let row = data_row(&[Some(&ct)]);
        assert!(decryptor.on_frame(b'D', &row).is_err());
    }

    #[test]
    fn mask_applies_after_decryption_and_to_plaintext() {
        let mask = MaskSpec { keep_first: 0, keep_last: 4, mask_with: '*' };
        let ctx = context_with(ReadColumn {
            name: "public.users.email".into(),
            transform: Some(transform(false)),
            mask: Some(mask),
        });
        let mut decryptor = ctx.decryptor(SessionPortals::new());
        decryptor.on_frame(b'T', &row_description(&[(1234, 1), (1234, 2)])).unwrap();

        // Decrypted value is masked before it reaches the client.
        let ct =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), b"4111111111111111")
                .unwrap();
        let row = data_row(&[Some(b"42"), Some(&ct)]);
        let rewritten = decryptor.on_frame(b'D', &row).unwrap().body().unwrap();
        assert_eq!(
            pgwire::parse_data_row(&rewritten).unwrap()[1],
            Some(b"************1111".as_slice())
        );

        // Pre-migration plaintext is masked too — the mask is a read policy.
        let plain_row = data_row(&[Some(b"42"), Some(b"4111111111111111")]);
        let rewritten = decryptor.on_frame(b'D', &plain_row).unwrap().body().unwrap();
        assert_eq!(
            pgwire::parse_data_row(&rewritten).unwrap()[1],
            Some(b"************1111".as_slice())
        );
    }

    #[test]
    fn text_format_bytea_keeps_its_hex_shape_through_the_mask() {
        let mask = MaskSpec { keep_first: 0, keep_last: 4, mask_with: '*' };
        let ctx = context_with(ReadColumn {
            name: "public.users.email".into(),
            transform: Some(transform(false)),
            mask: Some(mask),
        });
        let mut decryptor = ctx.decryptor(SessionPortals::new());
        decryptor.on_frame(b'T', &row_description(&[(1234, 2)])).unwrap();

        let ct =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), b"4111111111111111")
                .unwrap();
        let row = data_row(&[Some(format!("\\x{}", hex::encode(&ct)).as_bytes())]);
        let rewritten = decryptor.on_frame(b'D', &row).unwrap().body().unwrap();
        assert_eq!(
            pgwire::parse_data_row(&rewritten).unwrap()[0],
            Some(format!("\\x{}", hex::encode("************1111")).as_bytes())
        );
    }

    #[test]
    fn mask_only_column_masks_without_any_crypto() {
        let mask = MaskSpec { keep_first: 2, keep_last: 0, mask_with: '#' };
        let ctx = context_with(ReadColumn {
            name: "public.users.email".into(),
            transform: None,
            mask: Some(mask),
        });
        let mut decryptor = ctx.decryptor(SessionPortals::new());
        decryptor.on_frame(b'T', &row_description(&[(1234, 2)])).unwrap();

        let row = data_row(&[Some(b"secret")]);
        let rewritten = decryptor.on_frame(b'D', &row).unwrap().body().unwrap();
        assert_eq!(pgwire::parse_data_row(&rewritten).unwrap()[0], Some(b"se####".as_slice()));
    }

    /// The steady state of every driver with a prepared-statement cache: the
    /// statement is described once, and every later execution sends only
    /// Bind/Execute. Keying positions to the last RowDescription on the
    /// connection decrypted those rows with *another* statement's positions —
    /// or, as here, relayed a protected column as raw ciphertext (CL-3).
    #[test]
    fn a_cached_statement_decrypts_with_its_own_positions_not_the_last_described_ones() {
        let ctx = context(false);
        let (mut rewriter, mut decryptor) = session(&ctx);

        // Statement A: `id, email`, with email protected at position 1.
        prepare(&mut rewriter, b"a", b"SELECT id, email FROM users WHERE id = $1");
        decryptor.on_frame(b'T', &row_description(&[(1234, 1), (1234, 2)])).unwrap();
        decryptor.on_frame(b'Z', b"I").unwrap();

        // Statement B: `id, created_at`, nothing protected. Its RowDescription
        // is the last one the connection sees.
        prepare(&mut rewriter, b"b", b"SELECT id, created_at FROM users WHERE id = $1");
        decryptor.on_frame(b'T', &row_description(&[(1234, 1), (1234, 9)])).unwrap();
        decryptor.on_frame(b'Z', b"I").unwrap();

        // Re-executing A out of the driver's cache sends no Describe at all.
        execute(&mut rewriter, b"a");
        let ct =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), b"alice@example.com")
                .unwrap();
        let rewritten = decryptor
            .on_frame(b'D', &data_row(&[Some(b"42"), Some(&ct)]))
            .unwrap()
            .body()
            .expect("A's own positions must decrypt A's rows");
        assert_eq!(
            pgwire::parse_data_row(&rewritten).unwrap()[1],
            Some(b"alice@example.com".as_slice())
        );
        complete(&mut decryptor);

        // B's plaintext column is left alone: A's positions must not follow
        // the connection either.
        execute(&mut rewriter, b"b");
        assert!(decryptor
            .on_frame(b'D', &data_row(&[Some(b"42"), Some(b"2026-01-01")]))
            .unwrap()
            .body()
            .is_none());
    }

    /// The other half of the cached-statement story. A driver that describes
    /// once and then sends only Bind/Execute produces DataRows with no `'T'`
    /// in front of them, so nothing re-derives the mapping: a column whose
    /// protection is *added* after the Describe — an operator config change,
    /// or a first resolution that ran before the column existed — was relayed
    /// in its stored form for the whole life of the statement. Silently under
    /// `warn`, and with no `'T'` for `reject` to catch either (CL-3).
    #[test]
    fn a_cached_statement_picks_up_protection_added_after_it_was_described() {
        let ctx = Arc::new(RowContext::new(
            Resolved::default(),
            OnUnprotected::Warn,
            DEFAULT_MAX_PROTECTED_VALUE_LEN,
        ));
        let (mut rewriter, mut decryptor) = session(&ctx);

        prepare(&mut rewriter, b"a", b"SELECT id, email FROM users WHERE id = $1");
        decryptor.on_frame(b'T', &row_description(&[(1234, 1), (1234, 2)])).unwrap();
        decryptor.on_frame(b'Z', b"I").unwrap();

        // Nothing is protected yet, so the column relays. That is the state
        // the window opens in, and where it used to stay.
        let ct =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), b"alice@example.com")
                .unwrap();
        execute(&mut rewriter, b"a");
        let row = data_row(&[Some(b"42"), Some(&ct)]);
        assert!(decryptor.on_frame(b'D', &row).unwrap().body().is_none());
        complete(&mut decryptor);

        // A re-resolution now covers the position the statement was described
        // with. The driver sends no Describe — it already has one.
        let mut columns = ColumnMap::new();
        columns.insert(
            (1234, 2),
            ReadColumn {
                name: "public.users.email".into(),
                transform: Some(transform(false)),
                mask: None,
            },
        );
        ctx.publish(Resolved { columns, ..Default::default() });

        execute(&mut rewriter, b"a");
        // Twice: the second row proves the re-derivation was written back to
        // the portal rather than recomputed per row.
        for _ in 0..2 {
            let rewritten = decryptor
                .on_frame(b'D', &row)
                .unwrap()
                .body()
                .expect("a cached Execute must re-derive against the current resolution");
            assert_eq!(
                pgwire::parse_data_row(&rewritten).unwrap()[1],
                Some(b"alice@example.com".as_slice())
            );
        }
    }

    /// The other direction of the same re-derivation: a resolution that stops
    /// covering a position must not *un*protect it. When a column's
    /// `(table_oid, attnum)` moves, the rows of a statement described before
    /// the move are still in the form the old transform opens — the envelope
    /// keys by key id, not by OID — so a re-derivation that dropped the
    /// mapping would relay ciphertext where freezing it decrypted.
    #[test]
    fn a_re_resolution_that_moves_a_column_does_not_unprotect_a_cached_statement() {
        let ctx = context(false);
        let (mut rewriter, mut decryptor) = session(&ctx);

        prepare(&mut rewriter, b"a", b"SELECT id, email FROM users WHERE id = $1");
        decryptor.on_frame(b'T', &row_description(&[(1234, 1), (1234, 2)])).unwrap();
        decryptor.on_frame(b'Z', b"I").unwrap();

        // The table is recreated, so the column resolves somewhere else
        // entirely and nothing covers the described position any more.
        let mut columns = ColumnMap::new();
        columns.insert(
            (5678, 2),
            ReadColumn {
                name: "public.users.email".into(),
                transform: Some(transform(false)),
                mask: None,
            },
        );
        ctx.publish(Resolved {
            columns,
            names: HashSet::from(["email".to_owned()]),
            ..Default::default()
        });

        execute(&mut rewriter, b"a");
        let ct =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), b"alice@example.com")
                .unwrap();
        let rewritten = decryptor
            .on_frame(b'D', &data_row(&[Some(b"42"), Some(&ct)]))
            .unwrap()
            .body()
            .expect("the description keeps what it was described with");
        assert_eq!(
            pgwire::parse_data_row(&rewritten).unwrap()[1],
            Some(b"alice@example.com".as_slice())
        );
    }

    /// The frames a refusal put on the wire, as one buffer.
    fn refused(action: FrameAction) -> Vec<u8> {
        let FrameAction::RefuseAndClose(frames) = action else {
            panic!("expected a refusal, got {action:?}")
        };
        assert_eq!(frames[0], b'E', "a refusal is an ErrorResponse");
        frames
    }

    #[test]
    fn a_data_row_no_description_covers_is_refused_not_relayed() {
        let ctx = context(false);
        let (mut rewriter, mut decryptor) = session(&ctx);

        // Parse/Bind/Execute with no Describe anywhere: nothing on the
        // connection says what these columns are.
        rewriter
            .on_frame(
                b'P',
                &pgwire::encode_parse(b"a", b"SELECT email FROM users", &0i16.to_be_bytes()),
            )
            .unwrap();
        execute(&mut rewriter, b"a");
        let ct =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), b"alice@example.com")
                .unwrap();
        let row = data_row(&[Some(&ct)]);
        let error = refused(decryptor.on_frame(b'D', &row).unwrap());
        let text = String::from_utf8_lossy(&error);
        assert!(text.contains("42501"), "the client gets a SQLSTATE: {text}");
        assert!(text.contains("never described"), "and a reason: {text}");

        // Nor does a DataRow that follows no RowDescription at all pass.
        let mut untracked = context(false).decryptor(SessionPortals::new());
        refused(untracked.on_frame(b'D', &row).unwrap());
    }

    /// A read-path refusal tells the client why *and* ends the session. It
    /// cannot do only the first: the refused statement has already run, and the
    /// backend is still executing whatever the client sent after it. Relaying
    /// an error and then resynchronising on the backend's ReadyForQuery would
    /// let `SELECT protected; UPDATE …` commit its UPDATE behind an error
    /// saying the statement failed — and the relayed ReadyForQuery would carry
    /// the backend's real `I` status, telling the client no transaction is even
    /// open. Only closing the connection makes the backend roll that back.
    #[test]
    fn a_read_path_refusal_answers_the_client_and_ends_the_session() {
        let ctx = context(false);
        let (mut rewriter, mut decryptor) = session(&ctx);
        rewriter
            .on_frame(
                b'P',
                &pgwire::encode_parse(b"a", b"SELECT email FROM users", &0i16.to_be_bytes()),
            )
            .unwrap();
        execute(&mut rewriter, b"a");

        let ct =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), b"alice@example.com")
                .unwrap();
        let row = data_row(&[Some(&ct)]);
        let action = decryptor.on_frame(b'D', &row).unwrap();

        // The action itself is what ends the session, so the client is answered
        // and nothing after it is relayed. Anything short of RefuseAndClose
        // here would leave the batch running upstream.
        let frames = refused(action);
        let text = String::from_utf8_lossy(&frames);
        assert!(text.contains("42501"), "the client gets a SQLSTATE: {text}");
    }

    /// A migration that recreates the table or the column gives the protected
    /// column a new `(table_oid, attnum)`. The write path keys on names, so it
    /// carries on encrypting; this path keys on the old position, finds
    /// nothing, and used to relay the stored bytes with no signal at all
    /// (CL-3). The field's own label is the only handle the message offers.
    #[test]
    fn a_protected_column_at_an_unresolved_position_is_noticed_not_relayed_silently() {
        let ctx = context(false);
        let mut decryptor = ctx.decryptor(SessionPortals::new());

        // `email` is configured, but the table was recreated: new OID.
        let moved = named_row_description(&[("id", 5678, 1), ("email", 5678, 2)]);
        decryptor.on_frame(b'T', &moved).expect("warn mode relays");
        assert!(decryptor.warned_stale, "the session must report it once");

        // Once is enough — the flag is what stops a per-result-set flood.
        decryptor.warned_stale = false;
        decryptor.on_frame(b'T', &moved).unwrap();
        assert!(decryptor.warned_stale);

        // A field the map does cover is not suspect. Neither is a computed
        // column (table_oid 0) — for *this* check: there is no stale mapping
        // to re-resolve, so it is reported by the computed-column check
        // instead, which is a separate signal with a separate flag.
        let mut fine = context(false).decryptor(SessionPortals::new());
        fine.on_frame(b'T', &named_row_description(&[("email", 1234, 2)])).unwrap();
        fine.on_frame(b'T', &named_row_description(&[("email", 0, 0)])).unwrap();
        assert!(!fine.warned_stale);
        assert!(fine.warned_computed, "the computed column is still reported, just not as stale");
    }

    /// A protected column projected out of a derived table keeps its *name*
    /// but loses its table OID, so it matches no configured position and used
    /// to be relayed in its stored form. The write path cannot see this one:
    /// `SELECT email FROM (SELECT email FROM users) s` resolves `email`
    /// against the subquery, not against `users`, so the read path is the only
    /// place left to notice it.
    #[test]
    fn a_computed_protected_column_is_reported_rather_than_relayed() {
        // warn: relayed, but the operator is told, and only once.
        let mut warn = context(false).decryptor(SessionPortals::new());
        let computed = named_row_description(&[("email", 0, 0)]);
        warn.on_frame(b'T', &computed).expect("warn mode relays");
        assert!(warn.warned_computed, "the session must report it");

        warn.warned_computed = false;
        warn.on_frame(b'T', &computed).unwrap();
        assert!(warn.warned_computed, "still reported on a later result set");

        // reject: the client is answered instead of handed stored bytes.
        let mut decryptor = strict_context().decryptor(SessionPortals::new());
        let frames = refused(decryptor.on_frame(b'T', &computed).unwrap());
        let text = String::from_utf8_lossy(&frames);
        assert!(text.contains("42501"), "the client gets a SQLSTATE: {text}");
        assert!(text.contains("carries no table identity"), "{text}");
    }

    /// The mask-only case is the sharpest form of this: the column is stored
    /// as plaintext and the mask is the *only* thing protecting it, so a
    /// computed output hands back exactly what the mask exists to hide.
    #[test]
    fn a_computed_mask_only_column_is_reported() {
        let ctx = context_with(ReadColumn {
            name: "public.users.email".into(),
            transform: None,
            mask: Some(MaskSpec { keep_first: 0, keep_last: 4, mask_with: '*' }),
        });
        let mut decryptor = ctx.decryptor(SessionPortals::new());
        decryptor.on_frame(b'T', &named_row_description(&[("email", 0, 0)])).unwrap();
        assert!(decryptor.warned_computed, "an unmasked computed value must not pass unreported");
    }

    /// Under `on_unprotected = "reject"` the same detection refuses the result
    /// set rather than handing the client something that may be ciphertext —
    /// with the same ErrorResponse the write path answers a refused statement
    /// with, so the two halves of the setting behave alike.
    #[test]
    fn a_moved_protected_column_refuses_the_result_set_in_strict_mode() {
        let mut decryptor = strict_context().decryptor(SessionPortals::new());
        let error = refused(
            decryptor.on_frame(b'T', &named_row_description(&[("email", 5678, 2)])).unwrap(),
        );
        let text = String::from_utf8_lossy(&error);
        assert!(text.contains("42501") && text.contains("email"), "{text}");
    }

    /// A strict context over the same one configured column, for the checks
    /// whose whole point is what `reject` does differently.
    fn strict_context() -> Arc<RowContext> {
        let mut columns = ColumnMap::new();
        columns.insert(
            (1234, 2),
            ReadColumn {
                name: "public.users.email".into(),
                transform: Some(transform(false)),
                mask: None,
            },
        );
        Arc::new(RowContext::new(
            Resolved { columns, names: HashSet::from(["email".to_owned()]), ..Default::default() },
            OnUnprotected::Reject,
            DEFAULT_MAX_PROTECTED_VALUE_LEN,
        ))
    }

    /// The legacy fast path (`FunctionCall` `'F'` → `FunctionCallResponse`
    /// `'V'`) never goes through SQL, so the rewriter does not see it and no
    /// RowDescription precedes its answer. `'V'` used to fall through the
    /// catch-all arm and relay, which for a function that reads a protected
    /// column hands the client the stored form — and for a mask-only column
    /// the value the mask exists to hide.
    #[test]
    fn a_function_call_result_is_not_relayed_through_the_catch_all() {
        // warn: relayed, reported, and reported only once.
        let mut warn = context(false).decryptor(SessionPortals::new());
        assert!(warn.on_frame(b'V', b"\0\0\0\x04spam").unwrap().body().is_none());
        assert!(warn.warned_function_call, "the session must report it");
        warn.warned_function_call = false;
        warn.on_frame(b'V', b"\0\0\0\x04spam").unwrap();
        assert!(warn.warned_function_call, "still reported on a later call");

        // reject: the client is answered instead of handed the result.
        let mut strict = strict_context().decryptor(SessionPortals::new());
        let frames = refused(strict.on_frame(b'V', b"\0\0\0\x04spam").unwrap());
        let text = String::from_utf8_lossy(&frames);
        assert!(text.contains("42501"), "the client gets a SQLSTATE: {text}");
        assert!(text.contains("fast path"), "and a reason: {text}");
    }

    /// A FunctionCall body with no arguments: the rewriter does not parse it,
    /// but the shape is the protocol's so the frame is not a fiction.
    fn function_call_frame(oid: u32) -> Vec<u8> {
        let mut body = oid.to_be_bytes().to_vec();
        body.extend_from_slice(&0i16.to_be_bytes()); // argument format codes
        body.extend_from_slice(&0i16.to_be_bytes()); // arguments
        body.extend_from_slice(&0i16.to_be_bytes()); // result format code
        body
    }

    /// `'F'` is the one client message besides Sync and a simple Query that
    /// the backend answers with a ReadyForQuery of its own. Queueing nothing
    /// for it let that `'Z'` settle the *next* batch's marker: the batch
    /// pipelined behind it lost its Describe and Execute, its RowDescription
    /// landed on a later statement, and its rows were then matched against
    /// that statement's positions — relayed in their stored form when it
    /// protects nothing at that position (SEC-31).
    #[test]
    fn a_function_call_settles_its_own_ready_for_query() {
        let ctx = context(false);
        let (mut rewriter, mut decryptor) = session(&ctx);

        // A cached statement with nothing protected, sitting behind the batch
        // the desync used to eat.
        prepare(&mut rewriter, b"b", b"SELECT id, created_at FROM users WHERE id = $1");
        decryptor.on_frame(b'T', &row_description(&[(1234, 1), (1234, 9)])).unwrap();
        decryptor.on_frame(b'Z', b"I").unwrap();

        // FunctionCall, then Parse/Describe/Bind/Execute/Sync for a statement
        // whose second column is protected, then b's batch behind it.
        rewriter.on_frame(b'F', &function_call_frame(2000)).unwrap();
        rewriter
            .on_frame(
                b'P',
                &pgwire::encode_parse(
                    b"a",
                    b"SELECT id, email FROM users WHERE id = $1",
                    &0i16.to_be_bytes(),
                ),
            )
            .unwrap();
        rewriter.on_frame(b'D', b"Sa\0").unwrap();
        rewriter
            .on_frame(b'B', &pgwire::encode_bind(b"", b"a", &[], &[], &0i16.to_be_bytes()).unwrap())
            .unwrap();
        rewriter.on_frame(b'E', b"\0\0\0\0\0").unwrap();
        rewriter.on_frame(b'S', b"").unwrap();
        execute(&mut rewriter, b"b");

        // The fast path's own answer, then the ReadyForQuery it owes.
        assert!(decryptor.on_frame(b'V', b"\0\0\0\x04spam").unwrap().body().is_none());
        decryptor.on_frame(b'Z', b"I").unwrap();

        // a's RowDescription must land on a's own Execute.
        decryptor.on_frame(b'T', &row_description(&[(1234, 1), (1234, 2)])).unwrap();
        let ct =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), b"alice@example.com")
                .unwrap();
        let rewritten = decryptor
            .on_frame(b'D', &data_row(&[Some(b"42"), Some(&ct)]))
            .unwrap()
            .body()
            .expect("the function call's ReadyForQuery must not consume the batch behind it");
        assert_eq!(
            pgwire::parse_data_row(&rewritten).unwrap()[1],
            Some(b"alice@example.com".as_slice())
        );
        complete(&mut decryptor);

        // And b's batch is still lined up behind it.
        assert!(decryptor
            .on_frame(b'D', &data_row(&[Some(b"42"), Some(b"2026-01-01")]))
            .unwrap()
            .body()
            .is_none());
    }

    /// A re-resolution reaches sessions that are already open: the mapping is
    /// read per RowDescription, not captured when the session started.
    #[test]
    fn a_republished_resolution_is_picked_up_by_a_live_session() {
        let ctx = context(false);
        let mut decryptor = ctx.decryptor(SessionPortals::new());

        // Before: nothing is protected at the new position.
        decryptor.on_frame(b'T', &row_description(&[(5678, 2)])).unwrap();
        let ct =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), b"alice").unwrap();
        assert!(decryptor.on_frame(b'D', &data_row(&[Some(&ct)])).unwrap().body().is_none());

        // The refresher re-resolves the column to where it moved to.
        let mut columns = ColumnMap::new();
        columns.insert(
            (5678, 2),
            ReadColumn {
                name: "public.users.email".into(),
                transform: Some(transform(false)),
                mask: None,
            },
        );
        ctx.publish(Resolved {
            columns,
            names: HashSet::from(["email".to_owned()]),
            ..Default::default()
        });

        decryptor.on_frame(b'T', &row_description(&[(5678, 2)])).unwrap();
        let rewritten = decryptor
            .on_frame(b'D', &data_row(&[Some(&ct)]))
            .unwrap()
            .body()
            .expect("the new mapping decrypts");
        assert_eq!(pgwire::parse_data_row(&rewritten).unwrap()[0], Some(b"alice".as_slice()));
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let ctx = context(false);
        let mut decryptor = ctx.decryptor(SessionPortals::new());
        decryptor.on_frame(b'T', &row_description(&[(1234, 2)])).unwrap();

        let mut ct =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        let row = data_row(&[Some(&ct)]);
        assert!(decryptor.on_frame(b'D', &row).is_err());
    }

    /// The `\x` hex form has to be byte-identical to what the two-allocation
    /// `format!`/`hex::encode` pair produced, or a client decoding BYTEA text
    /// silently gets something else.
    #[test]
    fn hex_text_form_matches_the_representation_it_replaced() {
        for value in [b"".as_slice(), b"\x00", b"alice@example.com", &[0xff; 64]] {
            assert_eq!(
                hex_text_form(value),
                format!("\\x{}", hex::encode(value)).into_bytes(),
                "hex text form diverged for {value:?}"
            );
        }
    }

    /// A protected column larger than the ceiling is refused *before* it is
    /// decoded, opened and re-encoded — the chain of copies that made one
    /// oversized DataRow cost several times its own size (SEC-33). The refusal
    /// reaches the client as an ErrorResponse and ends the session, because
    /// the alternative is relaying a protected column's stored form.
    #[test]
    fn an_oversized_protected_value_is_refused_rather_than_decrypted() {
        let ctx = context(false);
        let mut decryptor = ctx.decryptor(SessionPortals::new());
        decryptor.on_frame(b'T', &row_description(&[(1234, 1), (1234, 2)])).unwrap();

        let oversized = vec![b'a'; DEFAULT_MAX_PROTECTED_VALUE_LEN + 1];
        let row = data_row(&[Some(b"42"), Some(&oversized)]);
        assert!(
            matches!(decryptor.on_frame(b'D', &row).unwrap(), FrameAction::RefuseAndClose(_)),
            "an oversized protected value must be refused, not relayed"
        );

        // The bound is on the protected column only: an unprotected column of
        // the same size is nothing this path copies, and still passes through.
        let wide = data_row(&[Some(&oversized), Some(b"plaintext")]);
        assert!(decryptor.on_frame(b'D', &wide).unwrap().body().is_none());
    }

    /// The boundary is inclusive, so a column right at the ceiling is not
    /// refused by it, and a large-but-sane protected value still decrypts.
    #[test]
    fn a_protected_value_at_the_ceiling_is_not_refused() {
        let ctx = context(false);
        let mut decryptor = ctx.decryptor(SessionPortals::new());
        decryptor.on_frame(b'T', &row_description(&[(1234, 2)])).unwrap();

        // Pre-migration plaintext of exactly the ceiling: nothing opens it, so
        // it relays — which is only reachable if the ceiling let it through.
        let at_ceiling = vec![b'p'; DEFAULT_MAX_PROTECTED_VALUE_LEN];
        let row = data_row(&[Some(&at_ceiling)]);
        assert!(decryptor.on_frame(b'D', &row).unwrap().body().is_none());

        let plaintext = vec![b'x'; 64 * 1024];
        let ct =
            envelope::encrypt(&KEY, &KEY_ID, &Binding::cell(&cell_context()), &plaintext).unwrap();
        let row = data_row(&[Some(&ct)]);
        let rewritten = decryptor.on_frame(b'D', &row).unwrap().body().unwrap();
        assert_eq!(pgwire::parse_data_row(&rewritten).unwrap()[0], Some(plaintext.as_slice()));
    }

    /// The per-row bound: replacements are counted as they are built, so a row
    /// whose rewrite would not fit a frame header is refused mid-assembly
    /// instead of after the whole oversized body has been allocated.
    #[test]
    fn a_row_whose_rewrite_outgrows_its_frame_is_refused_while_it_is_built() {
        // A multi-byte mask character is the cheapest way to make a rewrite
        // bigger than what arrived: every masked byte becomes three.
        let mask = MaskSpec { keep_first: 0, keep_last: 0, mask_with: '☃' };
        let column =
            ReadColumn { name: "public.users.email".into(), transform: None, mask: Some(mask) };
        let positions =
            vec![(0, column.clone(), RowKeyRef::Absent), (1, column, RowKeyRef::Absent)];
        let row = data_row(&[Some(b"aaaaaaaa"), Some(b"aaaaaaaa")]);

        // Room for the row that arrived and for the first replacement, but not
        // for the second — so the refusal lands before the row is finished.
        let max_body = row.len() + 16;
        let max_value = DEFAULT_MAX_PROTECTED_VALUE_LEN;
        let outgrown = RowDecryptor::decrypt_row(
            &positions,
            &ResultFormats::default(),
            &row,
            Bounds { max_value, max_body },
        )
        .expect_err("the rewrite does not fit");
        assert!(matches!(outgrown, Error::FrameTooLarge { msg_type: 'D', .. }));

        // Both halves of one memory policy classify the same way. The
        // per-value ceiling always answered the client; leaving the per-row
        // ceiling fatal dropped the socket with nothing sent, so one bound
        // read as a policy refusal and the other as a network fault (ERR-1).
        // A crypto failure is still fatal — that is the line these sit on the
        // other side of.
        assert!(is_refusal(&outgrown), "the per-row bound is a refusal, not a session failure");
        assert!(is_refusal(&Error::ProtectedValueTooLarge { position: 0, len: 2, max: 1 }));
        assert!(!is_refusal(&Error::Wire(dbsec_core::Error::Decrypt)));
        // What `is_refusal` decides is what the client is handed: an
        // ErrorResponse and a closed session, not a bare close.
        let mut decryptor = context(false).decryptor(SessionPortals::new());
        let frames = refused(decryptor.refuse(&outgrown));
        let text = String::from_utf8_lossy(&frames);
        assert!(text.contains("42501"), "the client gets a SQLSTATE: {text}");
        assert!(text.contains("byte limit"), "and the limit that refused it: {text}");

        // The same row under a bound that fits rewrites normally.
        let rewritten = RowDecryptor::decrypt_row(
            &positions,
            &ResultFormats::default(),
            &row,
            Bounds { max_value, max_body: pgwire::MAX_MESSAGE_LEN - 4 },
        )
        .unwrap();
        assert_eq!(
            pgwire::parse_data_row(&rewritten.unwrap()).unwrap(),
            vec![Some("☃".repeat(8).as_bytes()), Some("☃".repeat(8).as_bytes())]
        );
    }

    /// The per-value ceiling is the operator's `max_protected_value_bytes`, not
    /// a constant: what `decrypt_row` enforces is whatever the config carried,
    /// above *and* below the compiled-in default. A deployment whose protected
    /// column holds documents raises it and its reads stop being refused; one
    /// that wants a tighter bound than 16 MiB gets that too.
    #[test]
    fn the_configured_ceiling_is_what_the_read_path_enforces() {
        let mask = MaskSpec { keep_first: 0, keep_last: 4, mask_with: '*' };
        let positions = vec![(
            0,
            ReadColumn { name: "public.users.email".into(), transform: None, mask: Some(mask) },
            RowKeyRef::Absent,
        )];
        let row = data_row(&[Some(&vec![b'v'; 4096])]);
        let bounds = |max_value| Bounds { max_value, max_body: pgwire::MAX_MESSAGE_LEN - 4 };

        // Tighter than the default: refused, and the refusal names the
        // configured limit rather than the constant.
        assert!(matches!(
            RowDecryptor::decrypt_row(&positions, &ResultFormats::default(), &row, bounds(4095)),
            Err(Error::ProtectedValueTooLarge { position: 0, len: 4096, max: 4095 })
        ));
        // Exactly at it, and above it: both go through.
        for max_value in [4096, DEFAULT_MAX_PROTECTED_VALUE_LEN + 1] {
            assert!(
                RowDecryptor::decrypt_row(
                    &positions,
                    &ResultFormats::default(),
                    &row,
                    bounds(max_value)
                )
                .unwrap()
                .is_some(),
                "a value inside a ceiling of {max_value} must be masked, not refused"
            );
        }
    }
}
