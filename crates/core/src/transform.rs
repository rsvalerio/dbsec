//! `FieldTransform` — the core abstraction (milestone 5). Encryption is the
//! first implementation; FPE and HMAC tokenization arrive with the
//! pseudonymization milestone. Blind indexing rides along as a decorator
//! inside `EncryptTransform` (searchable columns), masking arrives later as a
//! read-path decorator.

use std::sync::Arc;

use crate::keys::KeySource;
use crate::{blind_index, envelope, Error};

pub trait FieldTransform: Send + Sync {
    /// Transforms a plaintext value into its stored form (write path).
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error>;

    /// Reverses `seal` (read path). `Ok(None)` means the value is not in this
    /// transform's stored form — pre-migration plaintext passes through.
    fn open(&self, stored: &[u8]) -> Result<Option<Vec<u8>>, Error>;
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
}
