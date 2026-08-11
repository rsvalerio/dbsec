//! `FieldTransform` — the core abstraction. Envelope encryption, FF1 FPE and
//! HMAC tokenization are the implementations. Blind indexing rides along as a
//! decorator inside `EncryptTransform` (searchable columns), masking arrives
//! later as a read-path decorator.

use std::sync::Arc;

use aes::Aes256;
use fpe::ff1::{FlexibleNumeralString, FF1};

use crate::keys::KeySource;
use crate::{blind_index, envelope, Error};

/// How a transform's stored form travels on the PostgreSQL wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireForm {
    /// Stored as BYTEA: `\x` hex in text format, raw bytes in binary format.
    Bytea,
    /// Stored in the column's original text shape (digits, hex token); the
    /// same bytes travel in both formats.
    Text,
}

pub trait FieldTransform: Send + Sync {
    /// Transforms a plaintext value into its stored form (write path).
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error>;

    /// Reverses `seal` (read path). `Ok(None)` means the value is not in this
    /// transform's stored form (or the transform is irreversible) — the value
    /// passes through untouched.
    fn open(&self, stored: &[u8]) -> Result<Option<Vec<u8>>, Error>;

    fn wire(&self) -> WireForm {
        WireForm::Bytea
    }

    /// The deterministic equality token a plaintext is stored under, for
    /// transforms that support equality search. `None` means equality WHERE
    /// clauses are left untouched.
    fn search_index(&self, _plaintext: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(None)
    }

    /// Whether `search_index` produces tokens — decides at SQL-rewrite time
    /// (before any plaintext exists) if a placeholder gets the equality
    /// rewrite.
    fn supports_search(&self) -> bool {
        false
    }
}

/// AES-256-GCM envelope encryption under the key source's active DEK, with an
/// optional blind index prepended for searchable columns.
pub struct EncryptTransform {
    keys: Arc<dyn KeySource>,
    /// Name of the deterministic index key; `Some` makes the column searchable.
    index_key: Option<String>,
}

impl EncryptTransform {
    pub fn new(keys: Arc<dyn KeySource>, index_key: Option<String>) -> Self {
        Self { keys, index_key }
    }

    pub fn searchable(&self) -> bool {
        self.index_key.is_some()
    }

    /// The blind index a plaintext would be stored under; the equality WHERE
    /// rewrite (searchable milestone) matches against this.
    pub fn blind_index(&self, plaintext: &[u8]) -> Result<Option<[u8; 32]>, Error> {
        match &self.index_key {
            Some(name) => {
                let index_key = self.keys.index_key(name)?;
                Ok(Some(blind_index::compute(&index_key, plaintext)))
            }
            None => Ok(None),
        }
    }
}

impl FieldTransform for EncryptTransform {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let (key_id, key) = self.keys.active_key()?;
        let sealed = envelope::encrypt(&key, &key_id, plaintext)?;
        match self.blind_index(plaintext)? {
            Some(index) => Ok(blind_index::prepend(&index, &sealed)),
            None => Ok(sealed),
        }
    }

    fn open(&self, stored: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let enveloped = match blind_index::split(stored) {
            Some((_index, enveloped)) if self.index_key.is_some() => enveloped,
            _ if envelope::is_enveloped(stored) => stored,
            _ => return Ok(None),
        };
        let id = envelope::key_id(enveloped)?;
        let key = self.keys.key(&id)?;
        envelope::decrypt(&key, enveloped).map(Some)
    }

    fn search_index(&self, plaintext: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.blind_index(plaintext)?.map(|index| index.to_vec()))
    }

    fn supports_search(&self) -> bool {
        self.index_key.is_some()
    }
}

/// FF1 refuses fewer digits than this — a 5-digit domain is brute-forceable
/// offline against the deterministic output (see plans/PLAN.md caveats).
pub const MIN_FPE_DIGITS: usize = 6;

/// FF1 format-preserving encryption over the decimal digits of a value.
/// Non-digit bytes (dashes, spaces) stay in place, so `4111-1111-1111-1111`
/// pseudonymizes to another string of the same shape. Deterministic under a
/// named index key; storage-free.
///
/// FPE output is indistinguishable from plaintext, so the read path cannot
/// detect pre-migration values: with `detokenize` enabled, a never-sealed
/// value decrypts to well-formed garbage. Migrate the column, or read raw.
pub struct FpeTransform {
    keys: Arc<dyn KeySource>,
    key_name: String,
    detokenize: bool,
}

impl FpeTransform {
    pub fn new(keys: Arc<dyn KeySource>, key_name: String, detokenize: bool) -> Self {
        Self { keys, key_name, detokenize }
    }

    /// Runs FF1 over the digit positions of `data`, leaving other bytes in
    /// place. `None` when the value has too few digits to be safe.
    fn transform_digits(&self, data: &[u8], decrypt: bool) -> Result<Option<Vec<u8>>, Error> {
        let positions: Vec<usize> =
            data.iter().enumerate().filter(|(_, b)| b.is_ascii_digit()).map(|(i, _)| i).collect();
        if positions.len() < MIN_FPE_DIGITS {
            return Ok(None);
        }
        let digits: Vec<u16> = positions.iter().map(|&i| u16::from(data[i] - b'0')).collect();

        let key = self.keys.index_key(&self.key_name)?;
        let ff1 = FF1::<Aes256>::new(key.as_ref(), 10)
            .map_err(|_| Error::Fpe("invalid FF1 key".into()))?;
        let numeral = FlexibleNumeralString::from(digits);
        let out = if decrypt { ff1.decrypt(&[], &numeral) } else { ff1.encrypt(&[], &numeral) }
            .map_err(|e| Error::Fpe(e.to_string()))?;

        let mut result = data.to_vec();
        for (&position, digit) in positions.iter().zip(Vec::<u16>::from(out)) {
            result[position] = b'0' + digit as u8;
        }
        Ok(Some(result))
    }
}

impl FieldTransform for FpeTransform {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        // Refusing to store a weakly-pseudonymized value beats a silent leak.
        self.transform_digits(plaintext, false)?.ok_or(Error::FpeDomain)
    }

    fn open(&self, stored: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if !self.detokenize {
            return Ok(None);
        }
        self.transform_digits(stored, true)
    }

    fn wire(&self) -> WireForm {
        WireForm::Text
    }
}

/// Irreversible HMAC-SHA256 tokenization for strings: the stored form is the
/// lowercase hex of the MAC under a named index key. Deterministic (equal
/// plaintexts get equal tokens — joins and equality still work), storage-free,
/// and never detokenized on read.
pub struct TokenTransform {
    keys: Arc<dyn KeySource>,
    key_name: String,
}

impl TokenTransform {
    pub fn new(keys: Arc<dyn KeySource>, key_name: String) -> Self {
        Self { keys, key_name }
    }
}

impl FieldTransform for TokenTransform {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let key = self.keys.index_key(&self.key_name)?;
        Ok(hex::encode(blind_index::compute(&key, plaintext)).into_bytes())
    }

    fn open(&self, _stored: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(None)
    }

    fn wire(&self) -> WireForm {
        WireForm::Text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{KeyId, KEY_ID_LEN};
    use crate::keys::Key;
    use zeroize::Zeroizing;

    const KEY: [u8; 32] = [7u8; 32];
    const KEY_ID: KeyId = [1u8; KEY_ID_LEN];
    const INDEX_KEY: [u8; 32] = [3u8; 32];

    struct TestKeys;

    impl KeySource for TestKeys {
        fn active_key(&self) -> Result<(KeyId, Key), Error> {
            Ok((KEY_ID, Zeroizing::new(KEY)))
        }
        fn key(&self, id: &KeyId) -> Result<Key, Error> {
            if id == &KEY_ID {
                Ok(Zeroizing::new(KEY))
            } else {
                Err(Error::UnknownKey("test".into()))
            }
        }
        fn index_key(&self, _name: &str) -> Result<Key, Error> {
            Ok(Zeroizing::new(INDEX_KEY))
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let t = EncryptTransform::new(Arc::new(TestKeys), None);
        let stored = t.seal(b"alice@example.com").unwrap();
        assert!(envelope::is_enveloped(&stored));
        assert_eq!(t.open(&stored).unwrap().unwrap(), b"alice@example.com");
        assert_eq!(t.open(b"plain old data").unwrap(), None);
    }

    #[test]
    fn searchable_seal_carries_blind_index() {
        let t = EncryptTransform::new(Arc::new(TestKeys), Some("users.email".into()));
        let stored = t.seal(b"alice").unwrap();
        let (index, _) = blind_index::split(&stored).unwrap();
        assert_eq!(index, blind_index::compute(&INDEX_KEY, b"alice"));
        assert_eq!(t.open(&stored).unwrap().unwrap(), b"alice");
    }

    #[test]
    fn fpe_preserves_shape_and_roundtrips() {
        let t = FpeTransform::new(Arc::new(TestKeys), "cards.pan".into(), true);
        let sealed = t.seal(b"4111-1111-1111-1111").unwrap();
        assert_ne!(sealed, b"4111-1111-1111-1111");
        assert_eq!(sealed.len(), 19);
        assert_eq!(sealed[4], b'-');
        assert!(sealed.iter().all(|b| b.is_ascii_digit() || *b == b'-'));
        assert_eq!(t.open(&sealed).unwrap().unwrap(), b"4111-1111-1111-1111");

        // Deterministic: same plaintext, same pseudonym.
        assert_eq!(t.seal(b"4111-1111-1111-1111").unwrap(), sealed);
        assert_eq!(t.wire(), WireForm::Text);
    }

    #[test]
    fn fpe_refuses_tiny_domains() {
        let t = FpeTransform::new(Arc::new(TestKeys), "users.pin".into(), true);
        assert!(matches!(t.seal(b"12345"), Err(Error::FpeDomain)));
        assert!(matches!(t.seal(b"no digits here"), Err(Error::FpeDomain)));
        // Reads of too-short values pass through instead of erroring.
        assert_eq!(t.open(b"12345").unwrap(), None);
    }

    #[test]
    fn fpe_without_detokenize_passes_reads_through() {
        let t = FpeTransform::new(Arc::new(TestKeys), "cards.pan".into(), false);
        let sealed = t.seal(b"123456789").unwrap();
        assert_eq!(t.open(&sealed).unwrap(), None);
    }

    #[test]
    fn token_is_deterministic_hex_and_irreversible() {
        let t = TokenTransform::new(Arc::new(TestKeys), "users.ssn".into());
        let token = t.seal(b"078-05-1120").unwrap();
        assert_eq!(token.len(), 64);
        assert!(token.iter().all(u8::is_ascii_hexdigit));
        assert_eq!(t.seal(b"078-05-1120").unwrap(), token);
        assert_ne!(t.seal(b"078-05-1121").unwrap(), token);
        assert_eq!(t.open(&token).unwrap(), None);
        assert_eq!(t.wire(), WireForm::Text);
    }
}
