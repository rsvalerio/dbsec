//! The dbsec ciphertext envelope:
//!
//! ```text
//! "DBS1" | key_id (16B) | nonce (12B) | AES-256-GCM ciphertext+tag
//! ```
//!
//! Values without the magic prefix are passed through untouched, which allows
//! gradual migration of plaintext columns.
//!
//! Nonces are random per invocation, so every DEK has a finite safe lifetime.
//! [`Cipher`] counts its own encryptions against [`MAX_ENCRYPTIONS_PER_KEY`],
//! and [`Ciphers`] — the per-process cache the write path goes through — rolls
//! to a fresh DEK once that budget is spent, or fails closed when the key
//! source has no other key to offer.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

use crate::keys::KeySource;
use crate::Error;

pub const MAGIC: &[u8; 4] = b"DBS1";
pub const KEY_ID_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = MAGIC.len() + KEY_ID_LEN + NONCE_LEN;

pub type KeyId = [u8; KEY_ID_LEN];

/// How many values one DEK may encrypt under random 96-bit nonces.
///
/// NIST SP 800-38D §8.3 caps a random-IV key at 2^32 invocations, which keeps
/// the nonce-collision probability below 2^-32. A repeated nonce under one key
/// leaks the XOR of two plaintexts and the GHASH authentication subkey — which
/// forges ciphertexts for that key — and the damage is retroactive across every
/// row already stored under it. The proxy encrypts once per protected value
/// rather than once per session, so the limit is reachable: it is enforced
/// (see [`Cipher::encrypt`]), not merely documented.
pub const MAX_ENCRYPTIONS_PER_KEY: u64 = 1 << 32;

/// Returns true if `data` carries the dbsec envelope magic.
pub fn is_enveloped(data: &[u8]) -> bool {
    data.len() > HEADER_LEN && data.starts_with(MAGIC)
}

/// AES-256-GCM bound to one DEK: the key schedule is built once, and the
/// random-nonce invocation budget is tracked for the life of the instance.
pub struct Cipher {
    cipher: Aes256Gcm,
    /// Encryptions charged against this key so far. Decryption is unlimited —
    /// only encryption draws nonces.
    used: AtomicU64,
    budget: u64,
}

impl Cipher {
    /// A cipher for `key` with the full [`MAX_ENCRYPTIONS_PER_KEY`] budget.
    pub fn new(key: &[u8; 32]) -> Self {
        Self::with_budget(key, MAX_ENCRYPTIONS_PER_KEY)
    }

    /// A cipher with a smaller budget, so tests can reach the boundary without
    /// performing 2^32 encryptions.
    pub fn with_budget(key: &[u8; 32], budget: u64) -> Self {
        Self { cipher: Aes256Gcm::new(key.into()), used: AtomicU64::new(0), budget }
    }

    /// Encryptions still allowed under this key.
    pub fn remaining(&self) -> u64 {
        self.budget.saturating_sub(self.used.load(Ordering::Relaxed))
    }

    /// Encrypts under a fresh random nonce, charging one invocation against
    /// this key's budget. `key_id` is stamped into the header and bound as AAD,
    /// so a value cannot be replayed under another key id.
    pub fn encrypt(&self, key_id: &KeyId, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        if self.used.fetch_add(1, Ordering::Relaxed) >= self.budget {
            return Err(Error::KeyExhausted(hex::encode(key_id)));
        }
        // The one deliberate exception to "cryptographic randomness comes from
        // the OS entropy source" (SEC-10), which `keys::FileKeySource` and the
        // proxy's Vault key source both follow. A GCM nonce is not key
        // material: it is public, it is stored in the clear in the header
        // above, and what it needs is unpredictability and non-repetition, not
        // long-term secrecy. `ThreadRng` gives that — ChaCha12 seeded from the
        // OS and periodically reseeded from it — and it is drawn once per
        // protected value on the data path, where `OsRng`'s `getrandom`
        // syscall would cost several times the AES work it accompanies.
        // Repetition is bounded separately, by MAX_ENCRYPTIONS_PER_KEY.
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);

        // AES-GCM encryption fails only past the ~64 GiB plaintext limit, and
        // pgwire::MAX_MESSAGE_LEN (1 GiB) already precludes that — so this is a
        // violated internal invariant, not a wrong key or tampering, and must
        // not be reported as Error::Decrypt.
        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: key_id })
            .map_err(|_| Error::Encrypt)?;

        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(key_id);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypts an enveloped value. The key id in the header is bound as AAD,
    /// so a value written under a different id fails authentication here.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if !is_enveloped(data) {
            return Err(Error::Malformed);
        }
        let id = &data[MAGIC.len()..MAGIC.len() + KEY_ID_LEN];
        let nonce = &data[MAGIC.len() + KEY_ID_LEN..HEADER_LEN];
        self.cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: &data[HEADER_LEN..], aad: id })
            .map_err(|_| Error::Decrypt)
    }
}

/// Per-key [`Cipher`] cache over a [`KeySource`]: each key schedule is built
/// once, and every column encrypting under the active DEK shares one invocation
/// budget for it. Build one per process and share it across transforms —
/// a budget counted per column would let N columns spend N × the limit.
pub struct Ciphers {
    keys: Arc<dyn KeySource>,
    budget: u64,
    /// The DEK new values are sealed under, resolved on first use. Both key
    /// sources fix it at startup, so it is re-resolved only once the budget is
    /// spent (see [`Ciphers::seal`]).
    active: RwLock<Option<(KeyId, Arc<Cipher>)>>,
    /// Read-path ciphers by key id. A key id the key source does not know fails
    /// before it reaches this map, so untrusted stored bytes cannot grow it:
    /// its size is bounded by the number of live DEKs.
    by_id: RwLock<HashMap<KeyId, Arc<Cipher>>>,
}

impl Ciphers {
    pub fn new(keys: Arc<dyn KeySource>) -> Self {
        Self::with_budget(keys, MAX_ENCRYPTIONS_PER_KEY)
    }

    /// A cache with a smaller per-key budget, for tests at the boundary.
    pub fn with_budget(keys: Arc<dyn KeySource>, budget: u64) -> Self {
        Self { keys, budget, active: RwLock::new(None), by_id: RwLock::new(HashMap::new()) }
    }

    /// The key source behind this cache, for the deterministic keys transforms
    /// need alongside their DEK.
    pub fn keys(&self) -> &Arc<dyn KeySource> {
        &self.keys
    }

    /// Seals a value under the active DEK. When that key's invocation budget is
    /// spent the key source is asked for a fresh one; if it offers the same key
    /// id, the write fails closed rather than reusing an exhausted key.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let (key_id, cipher) = self.active()?;
        match cipher.encrypt(&key_id, plaintext) {
            Err(Error::KeyExhausted(_)) => {
                let (key_id, cipher) = self.roll_active(&key_id)?;
                cipher.encrypt(&key_id, plaintext)
            }
            result => result,
        }
    }

    /// Opens an enveloped value under the DEK its header names.
    pub fn open(&self, enveloped: &[u8]) -> Result<Vec<u8>, Error> {
        let id = key_id(enveloped)?;
        self.for_id(&id)?.decrypt(enveloped)
    }

    fn active(&self) -> Result<(KeyId, Arc<Cipher>), Error> {
        if let Some((id, cipher)) = self.active.read().expect("ciphers lock").as_ref() {
            return Ok((*id, cipher.clone()));
        }
        let (id, key) = self.keys.active_key()?;
        let mut slot = self.active.write().expect("ciphers lock");
        let (id, cipher) =
            slot.get_or_insert_with(|| (id, Arc::new(Cipher::with_budget(&key, self.budget))));
        Ok((*id, cipher.clone()))
    }

    fn roll_active(&self, spent: &KeyId) -> Result<(KeyId, Arc<Cipher>), Error> {
        let (id, key) = self.keys.active_key()?;
        if id == *spent {
            return Err(Error::KeyExhausted(hex::encode(spent)));
        }
        let mut slot = self.active.write().expect("ciphers lock");
        // Another thread may have rolled already; its key is just as fresh.
        if let Some((current, cipher)) = slot.as_ref() {
            if current != spent {
                return Ok((*current, cipher.clone()));
            }
        }
        let cipher = Arc::new(Cipher::with_budget(&key, self.budget));
        *slot = Some((id, cipher.clone()));
        Ok((id, cipher))
    }

    fn for_id(&self, id: &KeyId) -> Result<Arc<Cipher>, Error> {
        if let Some(cipher) = self.by_id.read().expect("ciphers lock").get(id) {
            return Ok(cipher.clone());
        }
        let key = self.keys.key(id)?;
        let cipher = Arc::new(Cipher::with_budget(&key, self.budget));
        Ok(self.by_id.write().expect("ciphers lock").entry(*id).or_insert(cipher).clone())
    }
}

/// Encrypts one value under `key` with a fresh random nonce.
///
/// The raw primitive: a cipher built for a single call has no history, so it
/// carries no invocation budget. Production write paths go through
/// [`Ciphers::seal`], which enforces [`MAX_ENCRYPTIONS_PER_KEY`] per DEK.
pub fn encrypt(key: &[u8; 32], key_id: &KeyId, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    Cipher::new(key).encrypt(key_id, plaintext)
}

/// Extracts the key id from an enveloped value so the caller can look up the key.
pub fn key_id(data: &[u8]) -> Result<KeyId, Error> {
    if !is_enveloped(data) {
        return Err(Error::Malformed);
    }
    let mut id = [0u8; KEY_ID_LEN];
    id.copy_from_slice(&data[MAGIC.len()..MAGIC.len() + KEY_ID_LEN]);
    Ok(id)
}

/// Decrypts one enveloped value under `key`. [`Ciphers::open`] is the cached
/// equivalent for values arriving in bulk.
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Error> {
    Cipher::new(key).decrypt(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Key;
    use std::sync::atomic::AtomicU8;
    use zeroize::Zeroizing;

    const KEY: [u8; 32] = [7u8; 32];
    const KEY_ID: KeyId = [1u8; KEY_ID_LEN];

    /// A key source stuck on one DEK: it can never roll.
    struct OneKey;

    impl KeySource for OneKey {
        fn active_key(&self) -> Result<(KeyId, Key), Error> {
            Ok((KEY_ID, Zeroizing::new(KEY)))
        }
        fn key(&self, id: &KeyId) -> Result<Key, Error> {
            if id == &KEY_ID {
                Ok(Zeroizing::new(KEY))
            } else {
                Err(Error::UnknownKey(hex::encode(id)))
            }
        }
        fn index_key(&self, name: &str) -> Result<Key, Error> {
            Err(Error::UnknownKey(name.to_owned()))
        }
    }

    /// A key source that mints a new DEK every time it is asked for the active
    /// one — the rotating counterpart of `OneKey`.
    #[derive(Default)]
    struct RollingKeys {
        next: AtomicU8,
    }

    impl KeySource for RollingKeys {
        fn active_key(&self) -> Result<(KeyId, Key), Error> {
            let n = self.next.fetch_add(1, Ordering::Relaxed);
            Ok(([n; KEY_ID_LEN], Zeroizing::new([n; 32])))
        }
        fn key(&self, id: &KeyId) -> Result<Key, Error> {
            Ok(Zeroizing::new([id[0]; 32]))
        }
        fn index_key(&self, name: &str) -> Result<Key, Error> {
            Err(Error::UnknownKey(name.to_owned()))
        }
    }

    #[test]
    fn roundtrip() {
        let ct = encrypt(&KEY, &KEY_ID, b"secret").unwrap();
        assert!(is_enveloped(&ct));
        assert_eq!(key_id(&ct).unwrap(), KEY_ID);
        assert_eq!(decrypt(&KEY, &ct).unwrap(), b"secret");
    }

    #[test]
    fn tampering_is_detected() {
        let mut ct = encrypt(&KEY, &KEY_ID, b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        assert!(matches!(decrypt(&KEY, &ct), Err(Error::Decrypt)));
    }

    #[test]
    fn wrong_key_fails() {
        let ct = encrypt(&KEY, &KEY_ID, b"secret").unwrap();
        assert!(matches!(decrypt(&[8u8; 32], &ct), Err(Error::Decrypt)));
    }

    #[test]
    fn plaintext_passes_through_detection() {
        assert!(!is_enveloped(b"just a plain value"));
        assert!(matches!(decrypt(&KEY, b"plain"), Err(Error::Malformed)));
    }

    #[test]
    fn invocation_budget_is_spent_exactly_once_per_encryption() {
        let cipher = Cipher::with_budget(&KEY, 2);
        assert_eq!(cipher.remaining(), 2);
        let ct = cipher.encrypt(&KEY_ID, b"one").unwrap();
        assert_eq!(cipher.remaining(), 1);
        cipher.encrypt(&KEY_ID, b"two").unwrap();
        assert_eq!(cipher.remaining(), 0);

        // At the boundary the key is retired rather than reused.
        assert!(matches!(cipher.encrypt(&KEY_ID, b"three"), Err(Error::KeyExhausted(_))));
        assert!(matches!(cipher.encrypt(&KEY_ID, b"four"), Err(Error::KeyExhausted(_))));
        // Reading is not rationed: only encryption draws nonces.
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"one");
    }

    #[test]
    fn spent_budget_rolls_to_a_fresh_dek() {
        let ciphers = Ciphers::with_budget(Arc::new(RollingKeys::default()), 1);
        let first = ciphers.seal(b"one").unwrap();
        let second = ciphers.seal(b"two").unwrap();
        assert_ne!(key_id(&first).unwrap(), key_id(&second).unwrap());
        assert_eq!(ciphers.open(&first).unwrap(), b"one");
        assert_eq!(ciphers.open(&second).unwrap(), b"two");
    }

    #[test]
    fn spent_budget_fails_closed_when_the_key_source_cannot_roll() {
        let ciphers = Ciphers::with_budget(Arc::new(OneKey), 1);
        ciphers.seal(b"one").unwrap();
        assert!(matches!(ciphers.seal(b"two"), Err(Error::KeyExhausted(_))));
    }

    #[test]
    fn ciphers_open_rejects_unknown_key_ids() {
        let ciphers = Ciphers::new(Arc::new(OneKey));
        let foreign = encrypt(&KEY, &[9u8; KEY_ID_LEN], b"secret").unwrap();
        assert!(matches!(ciphers.open(&foreign), Err(Error::UnknownKey(_))));
        assert!(matches!(ciphers.open(b"plain"), Err(Error::Malformed)));
    }

    #[test]
    fn ciphers_reuse_one_instance_per_key_id() {
        let ciphers = Ciphers::new(Arc::new(OneKey));
        let sealed = ciphers.seal(b"secret").unwrap();
        assert_eq!(ciphers.open(&sealed).unwrap(), b"secret");
        assert_eq!(ciphers.open(&sealed).unwrap(), b"secret");
        assert_eq!(ciphers.by_id.read().unwrap().len(), 1);
    }
}
