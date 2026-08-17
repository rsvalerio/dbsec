//! Fuzzes the read path over untrusted stored bytes: masking, envelope opening
//! and FPE detokenization all run on whatever the database returned, which an
//! attacker with write access to it chooses. None of them may panic, no
//! transform may hand back a value it did not authenticate, and masking must
//! cover every position it claims to hide.

#![no_main]

use std::sync::Arc;

use dbsec_core::envelope::{CellContext, Ciphers, KeyId, KEY_ID_LEN};
use dbsec_core::keys::{Key, KeySource};
use dbsec_core::mask::MaskSpec;
use dbsec_core::transform::{EncryptTransform, FieldTransform, FpeTransform, TokenTransform};
use dbsec_core::Error;
use libfuzzer_sys::fuzz_target;

const KEY: [u8; 32] = [7u8; 32];
const KEY_ID: KeyId = [1u8; KEY_ID_LEN];
const INDEX_KEY: [u8; 32] = [3u8; 32];

struct FuzzKeys;

impl KeySource for FuzzKeys {
    fn active_key(&self) -> Result<(KeyId, Key), Error> {
        Ok((KEY_ID, Key::new(KEY)))
    }
    fn key(&self, id: &KeyId) -> Result<Key, Error> {
        if id == &KEY_ID {
            Ok(Key::new(KEY))
        } else {
            Err(Error::UnknownKey(hex::encode(id)))
        }
    }
    fn index_key(&self, _name: &str) -> Result<Key, Error> {
        Ok(Key::new(INDEX_KEY))
    }
}

fuzz_target!(|data: &[u8]| {
    // The first two bytes steer the mask spec; the rest is the stored value.
    let (keep_first, keep_last, stored) = match data {
        [first, last, rest @ ..] => (usize::from(*first % 8), usize::from(*last % 8), rest),
        _ => (0, 4, data),
    };

    let mask = MaskSpec { keep_first, keep_last, mask_with: '*' };
    let masked = mask.apply(stored);
    match std::str::from_utf8(stored) {
        // Masking is char-wise on UTF-8 and keeps the value's shape.
        Ok(text) => {
            let masked = std::str::from_utf8(&masked).expect("masking UTF-8 yields UTF-8");
            assert_eq!(masked.chars().count(), text.chars().count());
            let count = text.chars().count();
            let all_masked = count <= keep_first + keep_last;
            for (i, (plain, shown)) in text.chars().zip(masked.chars()).enumerate() {
                if all_masked || (i >= keep_first && i < count - keep_last) {
                    assert_eq!(shown, '*', "position {i} was not masked");
                } else {
                    assert_eq!(shown, plain);
                }
            }
        }
        // Non-UTF-8 is masked wholesale, one mask character per byte.
        Err(_) => assert_eq!(masked, vec![b'*'; stored.len()]),
    }

    let keys: Arc<dyn KeySource> = Arc::new(FuzzKeys);
    let ciphers = Arc::new(Ciphers::new(keys.clone()));

    for index_key in [None, Some("users.email".to_owned())] {
        let encrypt = EncryptTransform::new(
            ciphers.clone(),
            CellContext::new("public.users.email"),
            index_key,
        );
        // Arbitrary bytes cannot pass GCM authentication under a key the fuzzer
        // does not have, so an opened value would mean the envelope was read
        // without being verified.
        assert!(!matches!(encrypt.open(stored), Ok(Some(_))));
    }

    // FPE is shape-preserving in both directions: digits stay digits in place,
    // every other byte is untouched, and the length never changes.
    let fpe = FpeTransform::new(keys.clone(), "cards.pan".to_owned(), true);
    if let Ok(Some(opened)) = fpe.open(stored) {
        assert_eq!(opened.len(), stored.len());
        for (before, after) in stored.iter().zip(opened.iter()) {
            assert_eq!(before.is_ascii_digit(), after.is_ascii_digit());
            if !before.is_ascii_digit() {
                assert_eq!(before, after);
            }
        }
    }

    // Tokens are irreversible: reads always pass through.
    let token = TokenTransform::new(keys, "users.ssn".to_owned());
    assert!(matches!(token.open(stored), Ok(None)));
});
