//! `FieldTransform` — the core abstraction. Envelope encryption, FF1 FPE and
//! HMAC tokenization are the implementations. Blind indexing rides along as a
//! decorator inside `EncryptTransform` (searchable columns), masking arrives
//! later as a read-path decorator.

use std::sync::{Arc, OnceLock};

use aes::Aes256;
use fpe::ff1::{FlexibleNumeralString, FF1};

use crate::envelope::{CellContext, Ciphers};
use crate::keys::{Key, KeySource};
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

    /// Reverses `seal` (read path). `Ok(None)` is the passthrough contract: the
    /// value carries none of this transform's stored forms, so it is
    /// pre-migration plaintext (or the transform is irreversible) and travels
    /// to the client untouched.
    ///
    /// It must never stand in for "this looks like one of my stored forms but I
    /// cannot read it under the current config" — handing those bytes to the
    /// client would leak a stored form as if it were a value. Such a case is an
    /// error, or is opened anyway (see `EncryptTransform::open`).
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
///
/// The DEK ciphers come from a shared [`Ciphers`] cache, so every column
/// encrypting under the active key shares one key schedule and one invocation
/// budget for it.
pub struct EncryptTransform {
    ciphers: Arc<Ciphers>,
    /// The column this transform belongs to, bound into every envelope it
    /// writes so its ciphertexts authenticate nowhere else. One transform per
    /// protected column, so this is fixed for the transform's life.
    context: CellContext,
    /// Name of the deterministic index key; `Some` makes the column searchable.
    index_key_name: Option<String>,
    /// The index key itself, resolved on first use and reused per value.
    index_key: OnceLock<Key>,
}

impl EncryptTransform {
    pub fn new(ciphers: Arc<Ciphers>, context: CellContext, index_key: Option<String>) -> Self {
        Self { ciphers, context, index_key_name: index_key, index_key: OnceLock::new() }
    }

    pub fn searchable(&self) -> bool {
        self.index_key_name.is_some()
    }

    /// The deterministic index key, fetched from the key source once. Failures
    /// are not cached — only a successful lookup fills the cell.
    fn index_key(&self) -> Result<Option<&Key>, Error> {
        let Some(name) = &self.index_key_name else { return Ok(None) };
        if let Some(key) = self.index_key.get() {
            return Ok(Some(key));
        }
        let key = self.ciphers.keys().index_key(name)?;
        Ok(Some(self.index_key.get_or_init(|| key)))
    }

    /// The blind index a plaintext would be stored under; the equality WHERE
    /// rewrite (searchable milestone) matches against this.
    pub fn blind_index(&self, plaintext: &[u8]) -> Result<Option<[u8; 32]>, Error> {
        Ok(self.index_key()?.map(|key| blind_index::compute(key, plaintext)))
    }
}

impl FieldTransform for EncryptTransform {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let sealed = self.ciphers.seal(&self.context, plaintext)?;
        match self.blind_index(plaintext)? {
            Some(index) => Ok(blind_index::prepend(&index, &sealed)),
            None => Ok(sealed),
        }
    }

    fn open(&self, stored: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let enveloped = match blind_index::split(stored) {
            // An index prefix means the value was written while the column was
            // searchable. Open it whether or not the column is searchable now:
            // the index is only a search token and the envelope behind it is
            // self-describing, so turning `searchable` off stays reversible
            // instead of returning index-prefixed ciphertext to the client.
            Some((_index, enveloped)) => enveloped,
            None if envelope::is_enveloped(stored) => stored,
            // Neither stored form: pre-migration plaintext, passed through.
            None => return Ok(None),
        };
        self.ciphers.open(&self.context, enveloped).map(Some)
    }

    fn search_index(&self, plaintext: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.blind_index(plaintext)?.map(|index| index.to_vec()))
    }

    fn supports_search(&self) -> bool {
        self.index_key_name.is_some()
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
    /// FF1 under `key_name`: one AES-256 key schedule for the life of the
    /// transform rather than one per value.
    ff1: OnceLock<FF1<Aes256>>,
}

impl FpeTransform {
    pub fn new(keys: Arc<dyn KeySource>, key_name: String, detokenize: bool) -> Self {
        Self { keys, key_name, detokenize, ff1: OnceLock::new() }
    }

    /// The FF1 instance for this column's key, built on first use. Failures are
    /// not cached — only a successful lookup fills the cell.
    fn ff1(&self) -> Result<&FF1<Aes256>, Error> {
        if let Some(ff1) = self.ff1.get() {
            return Ok(ff1);
        }
        let key = self.keys.index_key(&self.key_name)?;
        // FF1::new rejects only a radix outside 2..=2^16, and 10 is a constant
        // here; the key is a fixed 32 bytes. Construction cannot fail.
        let ff1 = FF1::<Aes256>::new(key.as_ref(), 10).expect("radix 10 is a valid FF1 radix");
        Ok(self.ff1.get_or_init(|| ff1))
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

        let ff1 = self.ff1()?;
        let numeral = FlexibleNumeralString::from(digits);
        let out = if decrypt { ff1.decrypt(&[], &numeral) } else { ff1.encrypt(&[], &numeral) }
            .map_err(Error::Fpe)?;

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
    /// The HMAC key, resolved on first use and reused per value.
    key: OnceLock<Key>,
}

impl TokenTransform {
    pub fn new(keys: Arc<dyn KeySource>, key_name: String) -> Self {
        Self { keys, key_name, key: OnceLock::new() }
    }

    /// Failures are not cached — only a successful lookup fills the cell.
    fn key(&self) -> Result<&Key, Error> {
        if let Some(key) = self.key.get() {
            return Ok(key);
        }
        let key = self.keys.index_key(&self.key_name)?;
        Ok(self.key.get_or_init(|| key))
    }
}

impl FieldTransform for TokenTransform {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(hex::encode(blind_index::compute(self.key()?, plaintext)).into_bytes())
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

    const KEY: [u8; 32] = [7u8; 32];
    const KEY_ID: KeyId = [1u8; KEY_ID_LEN];
    const INDEX_KEY: [u8; 32] = [3u8; 32];

    struct TestKeys;

    impl KeySource for TestKeys {
        fn active_key(&self) -> Result<(KeyId, Key), Error> {
            Ok((KEY_ID, Key::new(KEY)))
        }
        fn key(&self, id: &KeyId) -> Result<Key, Error> {
            if id == &KEY_ID {
                Ok(Key::new(KEY))
            } else {
                Err(Error::UnknownKey("test".into()))
            }
        }
        fn index_key(&self, _name: &str) -> Result<Key, Error> {
            Ok(Key::new(INDEX_KEY))
        }
    }

    fn ciphers() -> Arc<Ciphers> {
        Arc::new(Ciphers::new(Arc::new(TestKeys)))
    }

    fn email() -> CellContext {
        CellContext::new("public.users.email")
    }

    #[test]
    fn seal_open_roundtrip() {
        let t = EncryptTransform::new(ciphers(), email(), None);
        let stored = t.seal(b"alice@example.com").unwrap();
        assert!(envelope::is_enveloped(&stored));
        assert_eq!(t.open(&stored).unwrap().unwrap(), b"alice@example.com");
        assert_eq!(t.open(b"plain old data").unwrap(), None);
    }

    #[test]
    fn searchable_seal_carries_blind_index() {
        let t = EncryptTransform::new(ciphers(), email(), Some("users.email".into()));
        let stored = t.seal(b"alice").unwrap();
        let (index, _) = blind_index::split(&stored).unwrap();
        assert_eq!(index, blind_index::compute(&INDEX_KEY, b"alice"));
        assert_eq!(t.open(&stored).unwrap().unwrap(), b"alice");
    }

    #[test]
    fn disabling_searchable_still_opens_index_prefixed_rows() {
        let shared = ciphers();
        let searchable = EncryptTransform::new(shared.clone(), email(), Some("users.email".into()));
        let stored = searchable.seal(b"alice@example.com").unwrap();

        // The same column after `searchable = false`: rows written under the
        // old config must still decrypt, never pass through as raw bytes.
        let plain = EncryptTransform::new(shared, email(), None);
        assert_eq!(plain.open(&stored).unwrap().unwrap(), b"alice@example.com");
        // The reverse direction (searchable turned on) keeps working too.
        let bare = searchable.open(&plain.seal(b"bob@example.com").unwrap()).unwrap();
        assert_eq!(bare.unwrap(), b"bob@example.com");
    }

    /// Two columns sharing one DEK still cannot read each other's stored
    /// bytes: whoever can write the table cannot relocate a value into a
    /// column it was not sealed for.
    #[test]
    fn a_value_relocated_into_another_column_fails_to_open() {
        let shared = ciphers();
        let ssn = EncryptTransform::new(shared.clone(), CellContext::new("public.users.ssn"), None);
        let card =
            EncryptTransform::new(shared, CellContext::new("public.users.credit_card"), None);

        let stored = ssn.seal(b"078-05-1120").unwrap();
        assert!(matches!(card.open(&stored), Err(Error::Decrypt)));
        assert_eq!(ssn.open(&stored).unwrap().unwrap(), b"078-05-1120");
    }

    /// The blind index travels with the envelope, so relocating a searchable
    /// value carries a valid-looking search token with it — the envelope
    /// underneath is still what refuses.
    #[test]
    fn relocating_a_searchable_value_fails_despite_a_valid_index_prefix() {
        let shared = ciphers();
        let ssn = EncryptTransform::new(
            shared.clone(),
            CellContext::new("public.users.ssn"),
            Some("public.users.ssn".into()),
        );
        let card = EncryptTransform::new(
            shared,
            CellContext::new("public.users.credit_card"),
            Some("public.users.credit_card".into()),
        );

        let stored = ssn.seal(b"078-05-1120").unwrap();
        assert!(blind_index::split(&stored).is_some(), "the stored form carries an index");
        assert!(matches!(card.open(&stored), Err(Error::Decrypt)));
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
