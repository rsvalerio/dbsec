//! End-to-end suite (milestone 10) for the OpenBao/Vault key source: the real
//! `dbsec` binary keyed by a live server rather than a keyfile.
//!
//! The interesting behaviour is what happens across restarts. Every startup
//! mints a fresh Transit data key, so rows written by an earlier run carry an
//! older key id: reading them proves the proxy fetched that id's wrapped DEK
//! from KV and unwrapped it through Transit. The deterministic keys must go
//! the other way — they are minted once and reused forever, which the blind
//! index makes visible, since an equality search only matches across restarts
//! if the same index key came back out of KV.
//!
//! Ignored by default — `make e2e-vault` starts OpenBao and Postgres and runs
//! it. `DBSEC_E2E_VAULT_ADDR` / `DBSEC_E2E_VAULT_TOKEN` override the defaults
//! (`http://127.0.0.1:8200`, `root` — a dev-mode server).

mod common;

use common::port_vault as port;

const TABLE: &str = "users_vault";

/// Offset of the envelope's key id within a searchable column's stored value:
/// blind index (32) + magic (4).
const KEY_ID_AT: std::ops::Range<usize> = 36..52;

fn vault_addr() -> String {
    std::env::var("DBSEC_E2E_VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_owned())
}

fn vault_token() -> String {
    std::env::var("DBSEC_E2E_VAULT_TOKEN").unwrap_or_else(|_| "root".to_owned())
}

/// A `[vault]` section pointing at the live server. Each run gets its own KV
/// path so a rerun starts from an empty key store — the point is watching the
/// keys being minted and then reused.
fn vault_section() -> String {
    let addr = vault_addr();
    let token = vault_token();
    let path = format!("dbsec-e2e/{}", std::process::id());
    format!(
        "[vault]\naddr = \"{addr}\"\ntoken = \"{token}\"\npath = \"{path}\"\n\
         transit_key = \"dbsec\"\n"
    )
}

/// Fails with a usable message when nothing is listening, instead of leaving
/// the proxy to die at startup and timing out on its port.
async fn require_vault() {
    let addr = vault_addr();
    let host_port = addr.split("//").nth(1).expect("vault addr has a scheme");
    if tokio::net::TcpStream::connect(host_port).await.is_err() {
        panic!("no OpenBao/Vault at {addr} — run `make e2e-vault`");
    }
}

#[tokio::test]
#[ignore = "needs the Postgres and OpenBao from `make e2e-vault`"]
async fn vault_key_source_survives_restarts() {
    require_vault().await;
    let direct = common::connect_direct().await;
    common::create_table(&direct, TABLE).await;

    let dir = tempfile::tempdir().unwrap();
    let opts = common::ProxyOpts {
        port: port(),
        table: TABLE,
        keys: common::Keys::Vault(vault_section()),
        strict: false,
    };

    // ---- First run: keys minted, rows sealed with this run's DEK. ----
    let proxy = common::spawn_proxy(dir.path(), &opts).await;
    let client = common::connect_via_proxy(dir.path(), port()).await;
    client
        .execute(
            &format!("INSERT INTO {TABLE} (email, phone, ssn, note) VALUES ($1, $2, $3, $4)"),
            &[&&b"lena@example.com"[..], &"555-606-7070", &"078-05-1120", &"lena-note"],
        )
        .await
        .unwrap();

    let row = client
        .query_one(&format!("SELECT email, phone, ssn, note FROM {TABLE} WHERE id = 1"), &[])
        .await
        .unwrap();
    assert_eq!(row.get::<_, Vec<u8>>(0), b"lena@example.com");
    assert_eq!(row.get::<_, &str>(1), "555-606-7070");
    assert_eq!(row.get::<_, &str>(2).len(), 64);
    assert_eq!(row.get::<_, &str>(3), "le*******");

    let stored =
        direct.query_one(&format!("SELECT email FROM {TABLE} WHERE id = 1"), &[]).await.unwrap();
    let first: Vec<u8> = stored.get(0);
    assert_eq!(&first[32..36], b"DBS2", "blind index then envelope magic");
    let first_key_id = first[KEY_ID_AT].to_vec();
    let first_index = first[..32].to_vec();

    proxy.shutdown().await;

    // ---- Second run: a new DEK, but the old rows must still open. ----
    let _proxy = common::spawn_proxy(dir.path(), &opts).await;
    let client = common::connect_via_proxy(dir.path(), port()).await;

    let row = client
        .query_one(&format!("SELECT email, phone FROM {TABLE} WHERE id = 1"), &[])
        .await
        .unwrap();
    assert_eq!(
        row.get::<_, Vec<u8>>(0),
        b"lena@example.com",
        "a DEK from the previous run must unwrap through Transit"
    );
    assert_eq!(row.get::<_, &str>(1), "555-606-7070", "FPE keys must survive the restart");

    // Deterministic keys came back from KV: the same plaintext still lands on
    // the same blind index, so a search written before the restart matches.
    let hits = client
        .query(&format!("SELECT id FROM {TABLE} WHERE email = $1"), &[&&b"lena@example.com"[..]])
        .await
        .unwrap();
    assert_eq!(hits.len(), 1, "the blind-index key was re-minted instead of reused");

    client
        .execute(
            &format!("INSERT INTO {TABLE} (email, phone) VALUES ($1, $2)"),
            &[&&b"lena@example.com"[..], &"555-606-7070"],
        )
        .await
        .unwrap();
    let stored =
        direct.query_one(&format!("SELECT email FROM {TABLE} WHERE id = 2"), &[]).await.unwrap();
    let second: Vec<u8> = stored.get(0);
    assert_eq!(second[..32], first_index[..], "blind index is stable across restarts");
    assert_ne!(second[KEY_ID_AT], first_key_id[..], "each startup seals under a fresh DEK");

    // Both key ids resolve at once: the row from run one and the row from run
    // two decrypt in the same result set.
    let rows = client.query(&format!("SELECT email FROM {TABLE} ORDER BY id"), &[]).await.unwrap();
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(row.get::<_, Vec<u8>>(0), b"lena@example.com");
    }
}
