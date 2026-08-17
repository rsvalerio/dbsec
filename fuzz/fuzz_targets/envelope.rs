//! Fuzzes the ciphertext envelope and blind-index split: arbitrary stored
//! bytes must never panic, and only authentic envelopes may decrypt.

#![no_main]

use libfuzzer_sys::fuzz_target;

const KEY: [u8; 32] = [7u8; 32];

fuzz_target!(|data: &[u8]| {
    let _ = dbsec_core::envelope::is_enveloped(data);
    let _ = dbsec_core::envelope::key_id(data);
    // Arbitrary input must never pass GCM authentication under this key.
    let context = dbsec_core::envelope::CellContext::new("public.users.email");
    assert!(dbsec_core::envelope::decrypt(&KEY, &context, data).is_err());
    if let Some((index, enveloped)) = dbsec_core::blind_index::split(data) {
        assert_eq!(index.len(), dbsec_core::blind_index::BLIND_INDEX_LEN);
        assert!(dbsec_core::envelope::is_enveloped(enveloped));
    }
});
