//! Property tests for the wire framing (milestone 2): no arbitrary byte string
//! may make a parser panic or over-read, and an encoded frame must parse back
//! to what went in.

use dbsec_pgwire::*;
use proptest::prelude::*;

proptest! {
    #[test]
    fn frame_headers_never_panic(header in any::<[u8; FRAME_HEADER_LEN]>()) {
        if let Ok((msg_type, body_len)) = frame_body_len(&header) {
            prop_assert_eq!(msg_type, header[0]);
            prop_assert!(body_len <= MAX_MESSAGE_LEN - 4);
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
        let body = encode_data_row(&cows).unwrap();
        let parsed = parse_data_row(&body).unwrap();
        prop_assert_eq!(parsed, values.iter().map(|v| v.as_deref()).collect::<Vec<_>>());
    }
    #[test]
    fn backend_message_parsers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_row_description(&data);
        let _ = parse_data_row(&data);
    }
    #[test]
    fn startup_lengths_never_panic(len_field in any::<[u8; 4]>()) {
        if let Ok(body_len) = startup_body_len(len_field) {
            // The startup cap, not the 1 GiB frame limit: no length a peer can
            // put on the wire may authorise a pre-auth allocation above it.
            prop_assert!((4..=MAX_STARTUP_MESSAGE_LEN - 4).contains(&body_len));
        }
    }
}
