//! Fuzzes every sans-io wire parser: none may panic or over-read on
//! arbitrary bytes (milestone 10).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 4 {
        let _ = dbsec_core::pgwire::startup_body_len(data[..4].try_into().unwrap());
    }
    if data.len() >= 5 {
        let _ = dbsec_core::pgwire::frame_body_len(data[..5].try_into().unwrap());
    }
    let _ = dbsec_core::pgwire::parse_row_description(data);
    if let Ok(values) = dbsec_core::pgwire::parse_data_row(data) {
        let cows: Vec<_> =
            values.iter().map(|v| v.map(std::borrow::Cow::Borrowed)).collect();
        // A parsed row has at most i16::MAX columns, so re-encoding it fits.
        let reencoded = dbsec_core::pgwire::encode_data_row(&cows).expect("row fits the wire");
        assert_eq!(dbsec_core::pgwire::parse_data_row(&reencoded).unwrap(), values);
    }
    let _ = dbsec_core::pgwire::parse_parse(data);
    if let Ok(bind) = dbsec_core::pgwire::parse_bind(data) {
        let cows: Vec<_> =
            bind.params.iter().map(|p| p.map(std::borrow::Cow::Borrowed)).collect();
        let reencoded = dbsec_core::pgwire::encode_bind(
            bind.portal,
            bind.statement,
            &bind.param_formats,
            &cows,
            bind.result_formats,
        )
        .expect("bind fits the wire");
        let reparsed = dbsec_core::pgwire::parse_bind(&reencoded).unwrap();
        assert_eq!(reparsed.params, bind.params);
        assert_eq!(reparsed.param_formats, bind.param_formats);
    }
});
