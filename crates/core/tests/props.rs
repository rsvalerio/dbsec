//! Property tests for the crypto core, the read path over untrusted stored
//! bytes, and wire framing (milestone 2).

use std::sync::Arc;

use dbsec_core::envelope::{self, Ciphers, KeyId, KEY_ID_LEN, NONCE_LEN};
use dbsec_core::keys::{Key, KeySource};
use dbsec_core::mask::MaskSpec;
use dbsec_core::transform::{EncryptTransform, FieldTransform, FpeTransform, TokenTransform};
use dbsec_core::{blind_index, pgwire, Error};
use proptest::prelude::*;
use zeroize::Zeroizing;

const TEST_KEY: [u8; 32] = [7u8; 32];
const TEST_KEY_ID: KeyId = [1u8; KEY_ID_LEN];
const TEST_INDEX_KEY: [u8; 32] = [3u8; 32];

/// Fixed keys, so a generated stored value is reproducible from the seed alone.
struct TestKeys;

impl KeySource for TestKeys {
    fn active_key(&self) -> Result<(KeyId, Key), Error> {
        Ok((TEST_KEY_ID, Zeroizing::new(TEST_KEY)))
    }
    fn key(&self, id: &KeyId) -> Result<Key, Error> {
        if id == &TEST_KEY_ID {
            Ok(Zeroizing::new(TEST_KEY))
        } else {
            Err(Error::UnknownKey(hex::encode(id)))
        }
    }
    fn index_key(&self, _name: &str) -> Result<Key, Error> {
        Ok(Zeroizing::new(TEST_INDEX_KEY))
    }
}

fn test_ciphers() -> Arc<Ciphers> {
    Arc::new(Ciphers::new(Arc::new(TestKeys)))
}

proptest! {
    #[test]
    fn envelope_roundtrips(
        key in any::<[u8; 32]>(),
        key_id in any::<[u8; KEY_ID_LEN]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let ct = envelope::encrypt(&key, &key_id, &plaintext).unwrap();
        prop_assert!(envelope::is_enveloped(&ct));
        prop_assert_eq!(envelope::key_id(&ct).unwrap(), key_id);
        prop_assert_eq!(envelope::decrypt(&key, &ct).unwrap(), plaintext);
    }

    #[test]
    fn flipping_any_byte_breaks_decryption(
        key in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..128),
        pos in any::<prop::sample::Index>(),
        flip in 1u8..,
    ) {
        let mut ct = envelope::encrypt(&key, &[1u8; KEY_ID_LEN], &plaintext).unwrap();
        let pos = pos.index(ct.len());
        ct[pos] ^= flip;
        // Corrupting the magic makes it non-enveloped; anything else must
        // fail authentication (key id is bound as AAD, nonce feeds the tag).
        match envelope::decrypt(&key, &ct) {
            Err(Error::Malformed) => prop_assert!(pos < envelope::MAGIC.len()),
            Err(Error::Decrypt) => prop_assert!(pos >= envelope::MAGIC.len()),
            Ok(_) => prop_assert!(false, "tampered ciphertext decrypted"),
            Err(e) => prop_assert!(false, "unexpected error: {e}"),
        }
    }

    #[test]
    fn decrypt_never_panics_on_arbitrary_input(
        key in any::<[u8; 32]>(),
        data in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let _ = envelope::decrypt(&key, &data);
        let _ = envelope::key_id(&data);
        let _ = envelope::is_enveloped(&data);
    }

    #[test]
    fn fresh_nonce_every_encryption(
        key in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let a = envelope::encrypt(&key, &[1u8; KEY_ID_LEN], &plaintext).unwrap();
        let b = envelope::encrypt(&key, &[1u8; KEY_ID_LEN], &plaintext).unwrap();
        let nonce = |ct: &[u8]| ct[4 + KEY_ID_LEN..4 + KEY_ID_LEN + NONCE_LEN].to_vec();
        prop_assert_ne!(nonce(&a), nonce(&b));
    }

    #[test]
    fn blind_index_is_deterministic_and_key_separated(
        index_key in any::<[u8; 32]>(),
        other_key in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let index = blind_index::compute(&index_key, &plaintext);
        prop_assert_eq!(index, blind_index::compute(&index_key, &plaintext));
        if index_key != other_key {
            prop_assert_ne!(index, blind_index::compute(&other_key, &plaintext));
        }
    }

    #[test]
    fn blind_index_roundtrips_through_storage_form(
        key in any::<[u8; 32]>(),
        index_key in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let ct = envelope::encrypt(&key, &[1u8; KEY_ID_LEN], &plaintext).unwrap();
        let index = blind_index::compute(&index_key, &plaintext);
        let stored = blind_index::prepend(&index, &ct);
        let (idx, env) = blind_index::split(&stored).unwrap();
        prop_assert_eq!(idx, index);
        prop_assert_eq!(envelope::decrypt(&key, env).unwrap(), plaintext);
    }

    #[test]
    fn blind_index_split_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = blind_index::split(&data);
    }

    #[test]
    fn frame_headers_never_panic(header in any::<[u8; pgwire::FRAME_HEADER_LEN]>()) {
        if let Ok((msg_type, body_len)) = pgwire::frame_body_len(&header) {
            prop_assert_eq!(msg_type, header[0]);
            prop_assert!(body_len <= pgwire::MAX_MESSAGE_LEN - 4);
        }
    }

    #[test]
    fn data_row_roundtrips(
        values in proptest::collection::vec(
            proptest::option::of(proptest::collection::vec(any::<u8>(), 0..64)),
            0..16,
        ),
    ) {
        let cows: Vec<_> =
            values.iter().map(|v| v.as_deref().map(std::borrow::Cow::Borrowed)).collect();
        let body = pgwire::encode_data_row(&cows).unwrap();
        let parsed = pgwire::parse_data_row(&body).unwrap();
        prop_assert_eq!(parsed, values.iter().map(|v| v.as_deref()).collect::<Vec<_>>());
    }

    #[test]
    fn backend_message_parsers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = pgwire::parse_row_description(&data);
        let _ = pgwire::parse_data_row(&data);
    }

    #[test]
    fn startup_lengths_never_panic(len_field in any::<[u8; 4]>()) {
        if let Ok(body_len) = pgwire::startup_body_len(len_field) {
            // The startup cap, not the 1 GiB frame limit: no length a peer can
            // put on the wire may authorise a pre-auth allocation above it.
            prop_assert!((4..=pgwire::MAX_STARTUP_MESSAGE_LEN - 4).contains(&body_len));
        }
    }

    /// Masking is a disclosure control, so the invariant is what it hides, not
    /// just that it does not panic: every position outside the kept prefix and
    /// suffix comes back as the mask character, and the value keeps its shape
    /// (same character count) so the client cannot infer content from length.
    #[test]
    fn mask_hides_every_unkept_character(
        value in ".{0,64}",
        keep_first in 0usize..8,
        keep_last in 0usize..8,
        mask_with in prop::sample::select(vec!['*', '#', 'x', '☃']),
    ) {
        let masked = MaskSpec { keep_first, keep_last, mask_with }.apply(value.as_bytes());
        let masked = String::from_utf8(masked).expect("masking UTF-8 yields UTF-8");

        let input: Vec<char> = value.chars().collect();
        let output: Vec<char> = masked.chars().collect();
        prop_assert_eq!(output.len(), input.len());

        // Too short to have a hidden middle: everything is masked.
        let fully_masked = input.len() <= keep_first + keep_last;
        for (i, (&plain, &shown)) in input.iter().zip(output.iter()).enumerate() {
            let kept = !fully_masked && (i < keep_first || i >= input.len() - keep_last);
            if kept {
                prop_assert_eq!(shown, plain);
            } else {
                prop_assert_eq!(shown, mask_with);
                if plain != mask_with {
                    prop_assert_ne!(shown, plain, "masked position {} leaked its input", i);
                }
            }
        }
    }

    /// Non-UTF-8 stored bytes are masked wholesale — one mask character per
    /// byte, nothing of the original surviving.
    #[test]
    fn mask_covers_every_byte_of_non_utf8_values(
        data in proptest::collection::vec(any::<u8>(), 0..128),
        keep_first in 0usize..8,
        keep_last in 0usize..8,
    ) {
        prop_assume!(std::str::from_utf8(&data).is_err());
        let masked = MaskSpec { keep_first, keep_last, mask_with: '*' }.apply(&data);
        prop_assert_eq!(masked, vec![b'*'; data.len()]);
    }

    /// The read path runs on whatever the database returned, which an attacker
    /// with write access to it chooses. No transform may panic on those bytes,
    /// and none may hand back a value it did not authenticate.
    #[test]
    fn transform_open_never_panics_on_arbitrary_stored_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let keys: Arc<dyn KeySource> = Arc::new(TestKeys);
        let ciphers = test_ciphers();

        for index_key in [None, Some("users.email".to_owned())] {
            let encrypt = EncryptTransform::new(ciphers.clone(), index_key);
            // Bytes the fuzzer chose cannot pass GCM authentication under a key
            // it does not have, so an opened plaintext would mean the envelope
            // was read without being verified.
            prop_assert!(!matches!(encrypt.open(&data), Ok(Some(_))));
        }

        let fpe = FpeTransform::new(keys.clone(), "cards.pan".into(), true);
        if let Some(opened) = fpe.open(&data)? {
            // FPE is shape-preserving in both directions: same length, digits
            // stay digits, everything else is untouched.
            prop_assert_eq!(opened.len(), data.len());
            for (before, after) in data.iter().zip(opened.iter()) {
                prop_assert_eq!(before.is_ascii_digit(), after.is_ascii_digit());
                if !before.is_ascii_digit() {
                    prop_assert_eq!(before, after);
                }
            }
        }

        // Tokens are irreversible and masking runs on the same untrusted bytes.
        prop_assert_eq!(TokenTransform::new(keys, "users.ssn".into()).open(&data)?, None);
        let _ = MaskSpec { keep_first: 2, keep_last: 4, mask_with: '*' }.apply(&data);
    }

    /// Turning `searchable` off must not change how already-stored rows read:
    /// the index prefix is a search token, not part of the value.
    #[test]
    fn stored_values_survive_a_searchable_config_change(
        plaintext in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let ciphers = test_ciphers();
        let searchable = EncryptTransform::new(ciphers.clone(), Some("users.email".into()));
        let plain = EncryptTransform::new(ciphers, None);

        let indexed = searchable.seal(&plaintext)?;
        let opened = plain.open(&indexed)?;
        prop_assert_eq!(opened.as_ref(), Some(&plaintext));

        let bare = plain.seal(&plaintext)?;
        let opened = searchable.open(&bare)?;
        prop_assert_eq!(opened.as_ref(), Some(&plaintext));
    }
}
