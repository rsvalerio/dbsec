//! The dbsec ciphertext envelope:
//!
//! ```text
//! "DBS1" | key_id (16B) | nonce (12B) | AES-256-GCM ciphertext+tag
//! ```
//!
//! Values without the magic prefix are passed through untouched, which allows
//! gradual migration of plaintext columns.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

use crate::Error;

pub const MAGIC: &[u8; 4] = b"DBS1";
pub const KEY_ID_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = MAGIC.len() + KEY_ID_LEN + NONCE_LEN;

pub type KeyId = [u8; KEY_ID_LEN];

/// Returns true if `data` carries the dbsec envelope magic.
pub fn is_enveloped(data: &[u8]) -> bool {
    data.len() > HEADER_LEN && data.starts_with(MAGIC)
}

pub fn encrypt(key: &[u8; 32], key_id: &KeyId, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: key_id })
        .map_err(|_| Error::Decrypt)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(key_id);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
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

pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Error> {
    if !is_enveloped(data) {
        return Err(Error::Malformed);
    }
    let id = &data[MAGIC.len()..MAGIC.len() + KEY_ID_LEN];
    let nonce = &data[MAGIC.len() + KEY_ID_LEN..HEADER_LEN];
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: &data[HEADER_LEN..], aad: id })
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];
    const KEY_ID: KeyId = [1u8; KEY_ID_LEN];

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
}
