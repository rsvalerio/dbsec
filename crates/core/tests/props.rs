//! Property tests for the crypto core and wire framing (milestone 2).

use dbsec_core::envelope::{self, KEY_ID_LEN, NONCE_LEN};
use dbsec_core::{blind_index, pgwire, Error};
use proptest::prelude::*;

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
        let body = pgwire::encode_data_row(&cows);
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
            prop_assert!((4..=pgwire::MAX_MESSAGE_LEN - 4).contains(&body_len));
        }
    }
}
