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
//! instead of relaying possibly-protected values (CL-3).
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
//! This path has four of them: a DataRow no described statement covers
//! ([`Error::UndescribedRow`]), a result column a stale mapping would
//! under-match ([`Error::StaleColumnMap`]), a result column named like a
//! protected one that carries no table identity at all
//! ([`Error::ComputedProtectedColumn`]) — a cast, an expression or a subquery
//! output, which PostgreSQL describes with `table_oid = 0` so no mapping can
//! ever cover it — and a protected value larger than
//! [`MAX_PROTECTED_VALUE_LEN`], which is refused rather than decrypted because
//! opening it costs several times its own size in transient memory (SEC-33).
//! The middle two are gated on `on_unprotected = "reject"`; the size ceiling,
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
use std::sync::{Arc, PoisonError};

use dbsec_core::mask::MaskSpec;
use dbsec_core::pgwire;
use dbsec_core::transform::{FieldTransform, WireForm};

use tokio::sync::Notify;

use crate::config::OnUnprotected;
use crate::portal::{Positions, RowSource, SessionPortals};
use crate::session::FrameAction;
use crate::Error;

/// Largest wire value the read path will decrypt, mask and re-encode for a
/// single protected column.
///
/// Field-level encryption protects fields — emails, identifiers, notes — so
/// this ceiling sits orders of magnitude above anything a configured
/// column realistically holds while keeping the decrypt path's allocation
/// amplification (see [`RowDecryptor::decrypt_row`]) bounded to tens of MiB
/// rather than the several GiB a value near the 1 GiB frame cap would cost.
/// A value over it is refused rather than relayed: passing it through would
/// hand the client a protected column's stored form, which is the one thing
/// this module never does.
pub const MAX_PROTECTED_VALUE_LEN: usize = 16 * 1024 * 1024;

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
}

/// Shared, per-process state for the decrypt path.
///
/// `resolved` is swapped by the refresher ([`crate::resolve::refresh_loop`]),
/// so a long-lived session picks up a re-resolution at its next
/// RowDescription without reconnecting. The lock is taken for a clone of one
/// `Arc` and never across an `.await`.
pub struct RowContext {
    resolved: std::sync::RwLock<Arc<Resolved>>,
    /// What a session does when a RowDescription looks like it was resolved
    /// against a schema that has since changed: warn, or fail the session.
    on_unprotected: OnUnprotected,
    /// Woken by a session that saw a suspect field, so a migration is picked
    /// up at the first read that notices it rather than at the next tick.
    refresh: Notify,
}

impl RowContext {
    pub fn new(resolved: Resolved, on_unprotected: OnUnprotected) -> Self {
        Self {
            resolved: std::sync::RwLock::new(Arc::new(resolved)),
            on_unprotected,
            refresh: Notify::new(),
        }
    }

    /// The current resolution. A poisoned lock means a session task panicked
    /// while holding it, which it can only have done between a clone and a
    /// swap — the value is intact either way.
    pub fn resolved(&self) -> Arc<Resolved> {
        self.resolved.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Publishes a fresh resolution to every live session.
    pub fn publish(&self, resolved: Resolved) {
        *self.resolved.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(resolved);
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
            | Error::ProtectedValueTooLarge { .. }
    )
}

impl RowDecryptor {
    /// Inspects one upstream→client frame and says what the relay does with
    /// it.
    ///
    /// A *refusal* — a DataRow no described statement covers, a result column
    /// a stale mapping would under-match under `on_unprotected = "reject"`, or
    /// a protected value over [`MAX_PROTECTED_VALUE_LEN`] — hands the client
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
                let positions: Positions = fields
                    .iter()
                    .enumerate()
                    .filter_map(|(i, f)| {
                        resolved
                            .columns
                            .get(&(f.table_oid, f.attnum))
                            .map(|column| (i, column.clone()))
                    })
                    .collect();
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
                    RowSource::Portal(positions) => positions,
                    RowSource::LastDescription => match &self.described {
                        Some(positions) => positions.clone(),
                        None => return Err(Error::UndescribedRow),
                    },
                    RowSource::Undescribed => return Err(Error::UndescribedRow),
                };
                if positions.is_empty() {
                    return Ok(None);
                }
                // `- 4` because the frame header's length field counts itself:
                // the same arithmetic `session::encode_frame_header` inverts.
                Self::decrypt_row(&positions, body, pgwire::MAX_MESSAGE_LEN - 4)
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
            _ => Ok(None),
        }
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
        let covered: HashSet<usize> = positions.iter().map(|(index, _)| *index).collect();
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
    /// 1. [`MAX_PROTECTED_VALUE_LEN`] caps each protected value, checked
    ///    before any copy of it is made;
    /// 2. `max_body` caps the row's projected re-encoded size, tracked as
    ///    replacements are built, so an oversized row is refused while it is
    ///    being assembled rather than after — which is all
    ///    `session::encode_frame_header` can do, since it sees the finished
    ///    body. It is a parameter rather than a constant so the bound is
    ///    testable without a gigabyte-sized fixture; production passes the
    ///    largest body a frame header can express.
    fn decrypt_row(
        positions: &[(usize, ReadColumn)],
        body: &[u8],
        max_body: usize,
    ) -> Result<Option<Vec<u8>>, Error> {
        let mut values: Vec<Option<Cow<'_, [u8]>>> =
            pgwire::parse_data_row(body)?.into_iter().map(|v| v.map(Cow::Borrowed)).collect();
        // `body` is exactly the encoding of `values`, so it is also the
        // starting point for what the rewritten row will encode to.
        let mut projected = body.len();
        let mut changed = false;
        for (position, column) in positions {
            let Some(Some(value)) = values.get_mut(*position) else { continue };
            if value.len() > MAX_PROTECTED_VALUE_LEN {
                return Err(Error::ProtectedValueTooLarge {
                    position: *position,
                    len: value.len(),
                    max: MAX_PROTECTED_VALUE_LEN,
                });
            }
            let (replacement, hex_text) = {
                let (stored, hex_text) = match &column.transform {
                    Some(transform) => decode_wire(transform.as_ref(), value),
                    None => (Cow::Borrowed(&**value), false),
                };
                let opened = match &column.transform {
                    Some(transform) => transform.open(&stored)?,
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
                if projected > max_body {
                    return Err(Error::FrameTooLarge {
                        msg_type: 'D',
                        body_len: projected,
                        max: max_body,
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
    use dbsec_core::envelope::{self, CellContext, KeyId, KEY_ID_LEN};
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
            true,
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

        let ct = envelope::encrypt(&KEY, &KEY_ID, &cell_context(), b"alice@example.com").unwrap();
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

        let ct = envelope::encrypt(&KEY, &KEY_ID, &cell_context(), b"alice").unwrap();
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

        let ct = envelope::encrypt(&KEY, &KEY_ID, &cell_context(), b"secret").unwrap();
        let row = data_row(&[Some(&ct)]);
        assert!(decryptor.on_frame(b'D', &row).unwrap().body().is_none());
    }

    #[test]
    fn unknown_key_fails_closed() {
        let ctx = context(false);
        let mut decryptor = ctx.decryptor(SessionPortals::new());
        decryptor.on_frame(b'T', &row_description(&[(1234, 2)])).unwrap();

        let ct = envelope::encrypt(&KEY, &[9u8; KEY_ID_LEN], &cell_context(), b"secret").unwrap();
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
        let ct = envelope::encrypt(&KEY, &KEY_ID, &cell_context(), b"4111111111111111").unwrap();
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

        let ct = envelope::encrypt(&KEY, &KEY_ID, &cell_context(), b"4111111111111111").unwrap();
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
        let ct = envelope::encrypt(&KEY, &KEY_ID, &cell_context(), b"alice@example.com").unwrap();
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
        let ct = envelope::encrypt(&KEY, &KEY_ID, &cell_context(), b"alice@example.com").unwrap();
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

        let ct = envelope::encrypt(&KEY, &KEY_ID, &cell_context(), b"alice@example.com").unwrap();
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
        let strict = Arc::new(RowContext::new(
            Resolved {
                columns: {
                    let mut columns = ColumnMap::new();
                    columns.insert(
                        (1234, 2),
                        ReadColumn { transform: Some(transform(false)), mask: None },
                    );
                    columns
                },
                names: HashSet::from(["email".to_owned()]),
                ..Default::default()
            },
            OnUnprotected::Reject,
        ));
        let mut decryptor = strict.decryptor(SessionPortals::new());
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
        let mut columns = ColumnMap::new();
        columns.insert((1234, 2), ReadColumn { transform: Some(transform(false)), mask: None });
        let ctx = Arc::new(RowContext::new(
            Resolved { columns, names: HashSet::from(["email".to_owned()]), ..Default::default() },
            OnUnprotected::Reject,
        ));
        let mut decryptor = ctx.decryptor(SessionPortals::new());
        let error = refused(
            decryptor.on_frame(b'T', &named_row_description(&[("email", 5678, 2)])).unwrap(),
        );
        let text = String::from_utf8_lossy(&error);
        assert!(text.contains("42501") && text.contains("email"), "{text}");
    }

    /// A re-resolution reaches sessions that are already open: the mapping is
    /// read per RowDescription, not captured when the session started.
    #[test]
    fn a_republished_resolution_is_picked_up_by_a_live_session() {
        let ctx = context(false);
        let mut decryptor = ctx.decryptor(SessionPortals::new());

        // Before: nothing is protected at the new position.
        decryptor.on_frame(b'T', &row_description(&[(5678, 2)])).unwrap();
        let ct = envelope::encrypt(&KEY, &KEY_ID, &cell_context(), b"alice").unwrap();
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

        let mut ct = envelope::encrypt(&KEY, &KEY_ID, &cell_context(), b"secret").unwrap();
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

        let oversized = vec![b'a'; MAX_PROTECTED_VALUE_LEN + 1];
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
        let at_ceiling = vec![b'p'; MAX_PROTECTED_VALUE_LEN];
        let row = data_row(&[Some(&at_ceiling)]);
        assert!(decryptor.on_frame(b'D', &row).unwrap().body().is_none());

        let plaintext = vec![b'x'; 64 * 1024];
        let ct = envelope::encrypt(&KEY, &KEY_ID, &cell_context(), &plaintext).unwrap();
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
        assert!(matches!(
            RowDecryptor::decrypt_row(&positions, &row, max_body),
            Err(Error::FrameTooLarge { msg_type: 'D', .. })
        ));
        // The same row under a bound that fits rewrites normally.
        let rewritten =
            RowDecryptor::decrypt_row(&positions, &row, pgwire::MAX_MESSAGE_LEN - 4).unwrap();
        assert_eq!(
            pgwire::parse_data_row(&rewritten.unwrap()).unwrap(),
            vec![Some("☃".repeat(8).as_bytes()), Some("☃".repeat(8).as_bytes())]
        );
    }
}
