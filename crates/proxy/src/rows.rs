//! The read path: RowDescription/DataRow interception in the upstream→client
//! relay. Configured columns are matched by table OID + attnum; values in a
//! transform's stored form are opened, then masked when a mask is configured.
//! Everything else passes through untouched. Crypto errors fail the session —
//! never a silent passthrough of ciphertext.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use dbsec_core::mask::MaskSpec;
use dbsec_core::pgwire;
use dbsec_core::transform::{FieldTransform, WireForm};

use crate::Error;

/// What the read path does to one column: open with the transform (when
/// present and readable), then mask what the client would see.
#[derive(Clone)]
pub struct ReadColumn {
    pub transform: Option<Arc<dyn FieldTransform>>,
    pub mask: Option<MaskSpec>,
}

/// Configured columns keyed by `(table oid, attnum)`, resolved at startup.
pub type ColumnMap = HashMap<(u32, i16), ReadColumn>;

/// Shared, per-process state for the decrypt path.
pub struct RowContext {
    pub columns: ColumnMap,
}

impl RowContext {
    pub fn decryptor(self: &Arc<Self>) -> RowDecryptor {
        RowDecryptor { ctx: self.clone(), active: Vec::new() }
    }
}

/// Per-session state: which positions of the current result set are
/// protected. Set by each RowDescription, used by the DataRows that follow.
pub struct RowDecryptor {
    ctx: Arc<RowContext>,
    active: Vec<(usize, ReadColumn)>,
}

impl RowDecryptor {
    /// Inspects one upstream→client frame. Returns a replacement body when
    /// the message must be rewritten, `None` to relay it untouched.
    pub fn on_frame(&mut self, msg_type: u8, body: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match msg_type {
            b'T' => {
                let fields = pgwire::parse_row_description(body)?;
                self.active = fields
                    .iter()
                    .enumerate()
                    .filter_map(|(i, f)| {
                        self.ctx
                            .columns
                            .get(&(f.table_oid, f.attnum))
                            .map(|column| (i, column.clone()))
                    })
                    .collect();
                Ok(None)
            }
            b'D' if !self.active.is_empty() => {
                let mut values: Vec<Option<Cow<'_, [u8]>>> = pgwire::parse_data_row(body)?
                    .into_iter()
                    .map(|v| v.map(Cow::Borrowed))
                    .collect();
                let mut changed = false;
                for (position, column) in &self.active {
                    let Some(Some(value)) = values.get_mut(*position) else { continue };
                    let opened = match &column.transform {
                        Some(transform) => open_value(transform.as_ref(), value)?,
                        None => None,
                    };
                    // Mask what the client would otherwise see: the opened
                    // plaintext, or the raw value when nothing opened.
                    let masked =
                        column.mask.map(|mask| mask.apply(opened.as_deref().unwrap_or(value)));
                    if let Some(replacement) = masked.or(opened) {
                        *value = Cow::Owned(replacement);
                        changed = true;
                    }
                }
                Ok(changed.then(|| pgwire::encode_data_row(&values)))
            }
            _ => Ok(None),
        }
    }
}

/// Opens one column value, or returns `None` for pre-migration plaintext.
/// BYTEA-form transforms see both wire representations: raw bytes (binary
/// format) and `\x`-prefixed hex (text format); text-form transforms (FPE,
/// tokens) get the bytes as-is. Opened plaintext is returned raw.
fn open_value(transform: &dyn FieldTransform, raw: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let decoded = match transform.wire() {
        WireForm::Bytea => raw.strip_prefix(b"\\x").and_then(|h| hex::decode(h).ok()),
        WireForm::Text => None,
    };
    let stored = decoded.as_deref().unwrap_or(raw);
    Ok(transform.open(stored)?)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use dbsec_core::envelope::{self, KeyId, KEY_ID_LEN};
    use dbsec_core::keys::{Key, KeySource};
    use dbsec_core::{blind_index, Error as CoreError};
    use zeroize::Zeroizing;

    pub const KEY: [u8; 32] = [7u8; 32];
    pub const KEY_ID: KeyId = [1u8; KEY_ID_LEN];
    pub const INDEX_KEY: [u8; 32] = [3u8; 32];

    pub struct OneKey;

    impl KeySource for OneKey {
        fn active_key(&self) -> Result<(KeyId, Key), CoreError> {
            Ok((KEY_ID, Zeroizing::new(KEY)))
        }
        fn key(&self, id: &KeyId) -> Result<Key, CoreError> {
            if id == &KEY_ID {
                Ok(Zeroizing::new(KEY))
            } else {
                Err(CoreError::UnknownKey(hex::encode(id)))
            }
        }
        fn index_key(&self, _name: &str) -> Result<Key, CoreError> {
            Ok(Zeroizing::new(INDEX_KEY))
        }
    }

    pub fn transform(searchable: bool) -> Arc<dyn FieldTransform> {
        let index_key = searchable.then(|| "public.users.email".to_owned());
        Arc::new(dbsec_core::transform::EncryptTransform::new(Arc::new(OneKey), index_key))
    }

    fn context_with(column: ReadColumn) -> Arc<RowContext> {
        let mut columns = ColumnMap::new();
        columns.insert((1234, 2), column);
        Arc::new(RowContext { columns })
    }

    fn context(searchable: bool) -> Arc<RowContext> {
        context_with(ReadColumn { transform: Some(transform(searchable)), mask: None })
    }

    fn row_description(fields: &[(u32, i16)]) -> Vec<u8> {
        let mut body = (fields.len() as i16).to_be_bytes().to_vec();
        for (table_oid, attnum) in fields {
            body.push(0); // empty name
            body.extend_from_slice(&table_oid.to_be_bytes());
            body.extend_from_slice(&attnum.to_be_bytes());
            body.extend_from_slice(&[0u8; 12]);
        }
        body
    }

    fn data_row(values: &[Option<&[u8]>]) -> Vec<u8> {
        let cows: Vec<_> = values.iter().map(|v| v.map(Cow::Borrowed)).collect();
        pgwire::encode_data_row(&cows)
    }

    #[test]
    fn decrypts_matched_columns_and_passes_others_through() {
        let ctx = context(false);
        let mut decryptor = ctx.decryptor();

        let desc = row_description(&[(1234, 1), (1234, 2)]);
        assert!(decryptor.on_frame(b'T', &desc).unwrap().is_none());

        let ct = envelope::encrypt(&KEY, &KEY_ID, b"alice@example.com").unwrap();
        let row = data_row(&[Some(b"42"), Some(&ct)]);
        let rewritten = decryptor.on_frame(b'D', &row).unwrap().unwrap();
        assert_eq!(
            pgwire::parse_data_row(&rewritten).unwrap(),
            vec![Some(b"42".as_slice()), Some(b"alice@example.com".as_slice())]
        );

        // Text-format (hex) representation decrypts too.
        let hex_row = data_row(&[Some(b"42"), Some(format!("\\x{}", hex::encode(&ct)).as_bytes())]);
        let rewritten = decryptor.on_frame(b'D', &hex_row).unwrap().unwrap();
        assert_eq!(
            pgwire::parse_data_row(&rewritten).unwrap()[1],
            Some(b"alice@example.com".as_slice())
        );

        // Plaintext (pre-migration) and NULL pass through untouched.
        let plain_row = data_row(&[Some(b"42"), Some(b"not encrypted")]);
        assert!(decryptor.on_frame(b'D', &plain_row).unwrap().is_none());
        let null_row = data_row(&[Some(b"42"), None]);
        assert!(decryptor.on_frame(b'D', &null_row).unwrap().is_none());
    }

    #[test]
    fn searchable_columns_lose_their_blind_index() {
        let ctx = context(true);
        let mut decryptor = ctx.decryptor();
        decryptor.on_frame(b'T', &row_description(&[(1234, 1), (1234, 2)])).unwrap();

        let ct = envelope::encrypt(&KEY, &KEY_ID, b"alice").unwrap();
        let index = blind_index::compute(&INDEX_KEY, b"alice");
        let stored = blind_index::prepend(&index, &ct);
        let row = data_row(&[Some(b"42"), Some(&stored)]);
        let rewritten = decryptor.on_frame(b'D', &row).unwrap().unwrap();
        assert_eq!(pgwire::parse_data_row(&rewritten).unwrap()[1], Some(b"alice".as_slice()));
    }

    #[test]
    fn unmatched_result_sets_relay_untouched() {
        let ctx = context(false);
        let mut decryptor = ctx.decryptor();
        decryptor.on_frame(b'T', &row_description(&[(9999, 1)])).unwrap();

        let ct = envelope::encrypt(&KEY, &KEY_ID, b"secret").unwrap();
        let row = data_row(&[Some(&ct)]);
        assert!(decryptor.on_frame(b'D', &row).unwrap().is_none());
    }

    #[test]
    fn unknown_key_fails_closed() {
        let ctx = context(false);
        let mut decryptor = ctx.decryptor();
        decryptor.on_frame(b'T', &row_description(&[(1234, 2)])).unwrap();

        let ct = envelope::encrypt(&KEY, &[9u8; KEY_ID_LEN], b"secret").unwrap();
        let row = data_row(&[Some(&ct)]);
        assert!(decryptor.on_frame(b'D', &row).is_err());
    }

    #[test]
    fn mask_applies_after_decryption_and_to_plaintext() {
        let mask = MaskSpec { keep_first: 0, keep_last: 4, mask_with: '*' };
        let ctx = context_with(ReadColumn { transform: Some(transform(false)), mask: Some(mask) });
        let mut decryptor = ctx.decryptor();
        decryptor.on_frame(b'T', &row_description(&[(1234, 1), (1234, 2)])).unwrap();

        // Decrypted value is masked before it reaches the client.
        let ct = envelope::encrypt(&KEY, &KEY_ID, b"4111111111111111").unwrap();
        let row = data_row(&[Some(b"42"), Some(&ct)]);
        let rewritten = decryptor.on_frame(b'D', &row).unwrap().unwrap();
        assert_eq!(
            pgwire::parse_data_row(&rewritten).unwrap()[1],
            Some(b"************1111".as_slice())
        );

        // Pre-migration plaintext is masked too — the mask is a read policy.
        let plain_row = data_row(&[Some(b"42"), Some(b"4111111111111111")]);
        let rewritten = decryptor.on_frame(b'D', &plain_row).unwrap().unwrap();
        assert_eq!(
            pgwire::parse_data_row(&rewritten).unwrap()[1],
            Some(b"************1111".as_slice())
        );
    }

    #[test]
    fn mask_only_column_masks_without_any_crypto() {
        let mask = MaskSpec { keep_first: 2, keep_last: 0, mask_with: '#' };
        let ctx = context_with(ReadColumn { transform: None, mask: Some(mask) });
        let mut decryptor = ctx.decryptor();
        decryptor.on_frame(b'T', &row_description(&[(1234, 2)])).unwrap();

        let row = data_row(&[Some(b"secret")]);
        let rewritten = decryptor.on_frame(b'D', &row).unwrap().unwrap();
        assert_eq!(pgwire::parse_data_row(&rewritten).unwrap()[0], Some(b"se####".as_slice()));
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let ctx = context(false);
        let mut decryptor = ctx.decryptor();
        decryptor.on_frame(b'T', &row_description(&[(1234, 2)])).unwrap();

        let mut ct = envelope::encrypt(&KEY, &KEY_ID, b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        let row = data_row(&[Some(&ct)]);
        assert!(decryptor.on_frame(b'D', &row).is_err());
    }
}
