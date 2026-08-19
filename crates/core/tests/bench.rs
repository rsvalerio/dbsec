//! Throughput measurement for the per-value seal/open path.
//!
//! Not a QA gate — it is a stopwatch, not an assertion. Run it with:
//!
//! ```text
//! cargo nextest run -p dbsec-core --release --test bench \
//!     --run-ignored ignored-only --no-capture
//! ```
//!
//! It exists to justify caching cipher state per key instead of rebuilding it
//! per value (an AES-256 key schedule, a key-map lookup and a key clone on
//! every value). Measured on one machine, same run conditions either side:
//!
//! ```text
//!                     per-value setup    cached (Ciphers/OnceLock)
//! encrypt seal            745k values/s      1541k values/s   2.1x
//! encrypt open            769k values/s      1624k values/s   2.1x
//! searchable seal         410k values/s       841k values/s   2.1x
//! searchable open         754k values/s      1743k values/s   2.3x
//! fpe seal                 41k values/s        59k values/s   1.4x
//! fpe open                 32k values/s        52k values/s   1.6x
//! token seal              719k values/s      1015k values/s   1.4x
//! ```

use std::sync::Arc;
use std::time::Instant;

use dbsec_core::envelope::{CellContext, Ciphers, KeyId, KEY_ID_LEN};
use dbsec_core::keys::{Key, KeySource};
use dbsec_core::transform::{EncryptTransform, FieldTransform, FpeTransform, TokenTransform};
use dbsec_core::Error;

const KEY: [u8; 32] = [7u8; 32];
const KEY_ID: KeyId = [1u8; KEY_ID_LEN];
const INDEX_KEY: [u8; 32] = [3u8; 32];
const VALUES: usize = 20_000;

struct BenchKeys;

impl KeySource for BenchKeys {
    fn active_key(&self) -> Result<(KeyId, Key), Error> {
        Ok((KEY_ID, Key::new(KEY)))
    }
    fn key(&self, _id: &KeyId) -> Result<Key, Error> {
        Ok(Key::new(KEY))
    }
    fn index_key(&self, _name: &str) -> Result<Key, Error> {
        Ok(Key::new(INDEX_KEY))
    }
}

fn report(label: &str, elapsed: std::time::Duration) {
    let per_value = elapsed.as_secs_f64() / VALUES as f64;
    println!("{label:<28} {:>9.0} values/s  ({:>6.2} µs/value)", 1.0 / per_value, per_value * 1e6);
}

fn measure(label: &str, mut op: impl FnMut(usize)) {
    for i in 0..1_000 {
        op(i);
    }
    let start = Instant::now();
    for i in 0..VALUES {
        op(i);
    }
    report(label, start.elapsed());
}

#[test]
#[ignore = "throughput measurement, not a correctness gate; run with --run-ignored ignored-only --no-capture"]
fn seal_open_throughput() {
    let keys: Arc<dyn KeySource> = Arc::new(BenchKeys);
    let plaintexts: Vec<Vec<u8>> =
        (0..256).map(|i| format!("alice{i:03}@example.com").into_bytes()).collect();
    let pans: Vec<Vec<u8>> =
        (0..256).map(|i| format!("4111-1111-1111-{i:04}").into_bytes()).collect();

    let ciphers = Arc::new(Ciphers::new(keys.clone()));
    let context = CellContext::new("public.users.email");
    let encrypt = EncryptTransform::new(ciphers.clone(), context.clone(), None);
    let searchable = EncryptTransform::new(ciphers, context, Some("users.email".into()));
    let fpe = FpeTransform::new(keys.clone(), "cards.pan".into(), true);
    let token = TokenTransform::new(keys.clone(), "users.ssn".into());

    let sealed: Vec<Vec<u8>> =
        plaintexts.iter().map(|p| encrypt.seal(p, None).expect("seal")).collect();
    let sealed_searchable: Vec<Vec<u8>> =
        plaintexts.iter().map(|p| searchable.seal(p, None).expect("seal")).collect();
    let sealed_fpe: Vec<Vec<u8>> = pans.iter().map(|p| fpe.seal(p, None).expect("seal")).collect();

    measure("encrypt seal", |i| {
        encrypt.seal(&plaintexts[i % plaintexts.len()], None).expect("seal");
    });
    measure("encrypt open", |i| {
        encrypt.open(&sealed[i % sealed.len()], None).expect("open");
    });
    measure("searchable seal", |i| {
        searchable.seal(&plaintexts[i % plaintexts.len()], None).expect("seal");
    });
    measure("searchable open", |i| {
        searchable.open(&sealed_searchable[i % sealed_searchable.len()], None).expect("open");
    });
    measure("fpe seal", |i| {
        fpe.seal(&pans[i % pans.len()], None).expect("seal");
    });
    measure("fpe open", |i| {
        fpe.open(&sealed_fpe[i % sealed_fpe.len()], None).expect("open");
    });
    measure("token seal", |i| {
        token.seal(&plaintexts[i % plaintexts.len()], None).expect("seal");
    });
}
