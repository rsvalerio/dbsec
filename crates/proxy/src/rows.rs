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
//! This path has five of them: a DataRow no described statement covers
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
//! like the undescribed row, is not. They hand the client a PostgreSQL
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

use dbsec_core::mask::MaskSpec;
use dbsec_core::pgwire;
use dbsec_core::sync::Unpoisoned as _;
use dbsec_core::transform::{FieldTransform, WireForm};

use tokio::sync::Notify;

use crate::config::OnUnprotected;
use crate::portal::{Positions, RowSource, SessionPortals};
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
    /// Which resolution this is, counting from the one built at startup.
    ///
    /// Assigned by [`RowContext::publish`] and ignored on the way in, so a
    /// caller building a `Resolved` never has to know about it. It exists so a
    /// [`Described`] can say which resolution it was computed against — see
    /// [`Described::rederived`].
    pub generation: u64,
}

impl Resolved {
    /// Which positions of a result set whose fields resolve to
    /// `(table_oid, attnum)` are protected, and what to do with each.
    fn protected(&self, fields: impl Iterator<Item = (u32, i16)>) -> Vec<(usize, ReadColumn)> {
        fields
            .enumerate()
            .filter_map(|(index, key)| self.columns.get(&key).map(|column| (index, column.clone())))
            .collect()
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
    /// `(table_oid, attnum)` of every field of the RowDescription, in order —
    /// the only part of it a later re-derivation needs. Six bytes per result
    /// column, held once per described statement.
    fields: Box<[(u32, i16)]>,
    /// The protected positions of that result set.
    columns: Vec<(usize, ReadColumn)>,
}

impl Described {
    fn new(resolved: &Resolved, fields: impl Iterator<Item = (u32, i16)>) -> Self {
        let fields: Box<[(u32, i16)]> = fields.collect();
        Self {
            generation: resolved.generation,
            columns: resolved.protected(fields.iter().copied()),
            fields,
        }
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
        let mut columns = resolved.protected(self.fields.iter().copied());
        for (index, column) in &self.columns {
            if !columns.iter().any(|(covered, _)| covered == index) {
                columns.push((*index, column.clone()));
            }
        }
        columns.sort_unstable_by_key(|(index, _)| *index);
        Self { generation: resolved.generation, columns, fields: self.fields.clone() }
    }

    pub fn columns(&self) -> &[(usize, ReadColumn)] {
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
                    fields.iter().map(|f| (f.table_oid, f.attnum)),
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
                let positions = match self.portals.row_source() {
                    // A cached statement's description can be arbitrarily old,
                    // so it is checked against the current resolution before
                    // it is used; a simple-protocol description was built from
                    // the `'T'` immediately in front of these rows.
                    RowSource::Portal(positions) => self.current(positions),
                    RowSource::LastDescription => match &self.described {
                        Some(positions) => positions.clone(),
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
        let covered: HashSet<usize> = positions.columns().iter().map(|(index, _)| *index).collect();
        let named_like_protected = |field: &pgwire::RowField<'_>| {
            std::str::from_utf8(field.name)
                .is_ok_and(|name| resolved.names.contains(&name.to_lowercase()))
        };

        // A field with no table identity that is still named like a protected
        // column: a cast or a subquery output, which keeps the column's name
        // but loses its OID. Nothing to re-resolve — there is no mapping that
        // could ever cover it — so this is reported on its own terms.
        //
        // The write path refuses the shapes it can see in the statement, but
        // it resolves names against the tables in scope, so a column projected
        // out of a derived table (`SELECT email FROM (SELECT email FROM users) s`)
        // is invisible to it and only surfaces here.
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
        positions: &[(usize, ReadColumn)],
        body: &[u8],
        bounds: Bounds,
    ) -> Result<Option<Vec<u8>>, Error> {
        let mut values: Vec<Option<Cow<'_, [u8]>>> =
            pgwire::parse_data_row(body)?.into_iter().map(|v| v.map(Cow::Borrowed)).collect();
        // `body` is exactly the encoding of `values`, so it is also the
        // starting point for what the rewritten row will encode to.
        let mut projected = body.len();
        let mut changed = false;
        for (position, column) in positions {
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
                    Some(transform) => transform.open(&stored, None)?,
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
            .map(|key| (*key, ReadColumn { transform: Some(transform(false)), mask: None }))
            .collect();
        let resolved = Resolved { columns, ..Default::default() };
        Arc::new(Described::new(&resolved, fields.into_iter()))
    }

    pub fn transform(searchable: bool) -> Arc<dyn FieldTransform> {
        let index_key = searchable.then(|| "public.users.email".to_owned());
        let ciphers = Arc::new(envelope::Ciphers::new(Arc::new(OneKey)));
        Arc::new(dbsec_core::transform::EncryptTransform::new(ciphers, cell_context(), index_key))
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
        context_with(ReadColumn { transform: Some(transform(searchable)), mask: None })
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
        use crate::columns::ProtectedColumn;
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
            Arc::new(std::sync::atomic::AtomicU8::new(b'I')),
            crate::encrypt::StartupSettings::default(),
        );
        (rewriter, ctx.decryptor(portals))
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
        let ctx = context_with(ReadColumn { transform: Some(transform(false)), mask: Some(mask) });
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
        let ctx = context_with(ReadColumn { transform: Some(transform(false)), mask: Some(mask) });
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
        let ctx = context_with(ReadColumn { transform: None, mask: Some(mask) });
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
        columns.insert((1234, 2), ReadColumn { transform: Some(transform(false)), mask: None });
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
        columns.insert((5678, 2), ReadColumn { transform: Some(transform(false)), mask: None });
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
        columns.insert((1234, 2), ReadColumn { transform: Some(transform(false)), mask: None });
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
        columns.insert((5678, 2), ReadColumn { transform: Some(transform(false)), mask: None });
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
        let column = ReadColumn { transform: None, mask: Some(mask) };
        let positions = vec![(0, column.clone()), (1, column)];
        let row = data_row(&[Some(b"aaaaaaaa"), Some(b"aaaaaaaa")]);

        // Room for the row that arrived and for the first replacement, but not
        // for the second — so the refusal lands before the row is finished.
        let max_body = row.len() + 16;
        let max_value = DEFAULT_MAX_PROTECTED_VALUE_LEN;
        assert!(matches!(
            RowDecryptor::decrypt_row(&positions, &row, Bounds { max_value, max_body }),
            Err(Error::FrameTooLarge { msg_type: 'D', .. })
        ));
        // The same row under a bound that fits rewrites normally.
        let rewritten = RowDecryptor::decrypt_row(
            &positions,
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
        let positions = vec![(0, ReadColumn { transform: None, mask: Some(mask) })];
        let row = data_row(&[Some(&vec![b'v'; 4096])]);
        let bounds = |max_value| Bounds { max_value, max_body: pgwire::MAX_MESSAGE_LEN - 4 };

        // Tighter than the default: refused, and the refusal names the
        // configured limit rather than the constant.
        assert!(matches!(
            RowDecryptor::decrypt_row(&positions, &row, bounds(4095)),
            Err(Error::ProtectedValueTooLarge { position: 0, len: 4096, max: 4095 })
        ));
        // Exactly at it, and above it: both go through.
        for max_value in [4096, DEFAULT_MAX_PROTECTED_VALUE_LEN + 1] {
            assert!(
                RowDecryptor::decrypt_row(&positions, &row, bounds(max_value)).unwrap().is_some(),
                "a value inside a ceiling of {max_value} must be masked, not refused"
            );
        }
    }
}
