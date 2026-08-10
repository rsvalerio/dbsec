//! Deterministic blind index for searchable encryption (Acra's approach):
//! `hmac_sha256(index_key, plaintext)` prepended to the ciphertext envelope.
//! Deterministic by design, so it leaks equality and frequency patterns —
//! an accepted trade-off (see plans/PLAN.md caveats).

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::envelope;

pub const BLIND_INDEX_LEN: usize = 32;

/// Computes the blind index for a plaintext under an index key.
pub fn compute(index_key: &[u8; 32], plaintext: &[u8]) -> [u8; BLIND_INDEX_LEN] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(index_key).expect("HMAC accepts keys of any length");
    mac.update(plaintext);
    mac.finalize().into_bytes().into()
}

/// Builds the stored form of a searchable column: `index || envelope`.
pub fn prepend(index: &[u8; BLIND_INDEX_LEN], enveloped: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BLIND_INDEX_LEN + enveloped.len());
    out.extend_from_slice(index);
    out.extend_from_slice(enveloped);
    out
}

/// Splits a stored searchable value into `(index, envelope)`. Returns `None`
/// when the value doesn't carry an envelope after the index — i.e. plaintext
/// from before migration, which passes through untouched.
pub fn split(stored: &[u8]) -> Option<(&[u8], &[u8])> {
    let (index, rest) = stored.split_at_checked(BLIND_INDEX_LEN)?;
    envelope::is_enveloped(rest).then_some((index, rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope;

    const INDEX_KEY: [u8; 32] = [3u8; 32];

    #[test]
    fn deterministic_and_key_separated() {
        assert_eq!(compute(&INDEX_KEY, b"alice"), compute(&INDEX_KEY, b"alice"));
        assert_ne!(compute(&INDEX_KEY, b"alice"), compute(&INDEX_KEY, b"bob"));
        assert_ne!(compute(&INDEX_KEY, b"alice"), compute(&[4u8; 32], b"alice"));
    }

    #[test]
    fn prepend_split_roundtrip() {
        let ct = envelope::encrypt(&[7u8; 32], &[1u8; 16], b"alice").unwrap();
        let index = compute(&INDEX_KEY, b"alice");
        let stored = prepend(&index, &ct);
        let (idx, env) = split(&stored).unwrap();
        assert_eq!(idx, index);
        assert_eq!(env, ct);
    }

    #[test]
    fn split_rejects_non_enveloped_values() {
        assert!(split(b"short").is_none());
        assert!(split(&[0u8; 64]).is_none());
    }
}
