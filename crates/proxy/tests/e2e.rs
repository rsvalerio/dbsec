//! End-to-end suite (milestone 10): the real `dbsec` binary between
//! tokio-postgres (both protocols) and a real Postgres, with TLS on the
//! client hop. The sibling suites cover the other drivers (`e2e_sqlx`,
//! `e2e_psycopg`) and the OpenBao key source (`e2e_vault`).
//!
//! Ignored by default — `make e2e` starts the database and runs it.

mod common;

use common::port_tokio_postgres as port;

const TABLE: &str = "users";

#[tokio::test]
#[ignore = "needs the Postgres from `make e2e`"]
async fn transparent_encryption_end_to_end() {
    let direct = common::connect_direct().await;
    common::create_table(&direct, TABLE).await;

    let dir = tempfile::tempdir().unwrap();
    let _proxy =
        common::spawn_proxy(dir.path(), &common::ProxyOpts::file_keys(port(), TABLE)).await;
    let client = common::connect_via_proxy(dir.path(), port()).await;

    // Extended protocol: Parse/Bind with binary and text params.
    client
        .execute(
            "INSERT INTO users (email, phone, ssn, note) VALUES ($1, $2, $3, $4)",
            &[&&b"alice@example.com"[..], &"555-123-4567", &"078-05-1120", &"topsecret"],
        )
        .await
        .unwrap();

    // Simple protocol: literals sealed by the SQL rewrite.
    client
        .simple_query(
            "INSERT INTO users (email, phone, ssn, note) VALUES ('bob@example.com', '555-999-8888', '219-09-9999', 'alsohidden')",
        )
        .await
        .unwrap();

    // Reads through the proxy come back decrypted / pseudonymized / masked.
    let rows =
        client.query("SELECT email, phone, ssn, note FROM users ORDER BY id", &[]).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<_, Vec<u8>>(0), b"alice@example.com");
    assert_eq!(rows[0].get::<_, &str>(1), "555-123-4567"); // FPE detokenized
    let token: &str = rows[0].get(2); // tokens are irreversible
    assert_eq!(token.len(), 64);
    assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(rows[0].get::<_, &str>(3), "to*******"); // masked
    assert_eq!(rows[1].get::<_, Vec<u8>>(0), b"bob@example.com");
    assert_eq!(rows[1].get::<_, &str>(1), "555-999-8888");

    // Searchable equality: blind-index rewrite, via placeholder and literal.
    let hits = client
        .query("SELECT id FROM users WHERE email = $1", &[&&b"alice@example.com"[..]])
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    let hits =
        client.simple_query("SELECT id FROM users WHERE email = 'bob@example.com'").await.unwrap();
    let data_rows =
        hits.iter().filter(|m| matches!(m, tokio_postgres::SimpleQueryMessage::Row(_))).count();
    assert_eq!(data_rows, 1);
    let misses = client
        .query("SELECT id FROM users WHERE email = $1", &[&&b"nobody@example.com"[..]])
        .await
        .unwrap();
    assert!(misses.is_empty());

    // At rest (direct connection): everything is sealed.
    let stored = direct
        .query_one("SELECT email, phone, ssn, note FROM users WHERE id = 1", &[])
        .await
        .unwrap();
    let email: Vec<u8> = stored.get(0);
    assert_eq!(&email[32..36], b"DBS1", "blind index then envelope magic");
    assert_ne!(stored.get::<_, &str>(1), "555-123-4567");
    assert_eq!(stored.get::<_, &str>(1).len(), 12, "FPE keeps the shape");
    assert_eq!(stored.get::<_, &str>(2).len(), 64, "HMAC token at rest");
    assert_eq!(stored.get::<_, &str>(3), "topsecret", "mask-only stays plaintext at rest");

    // Deterministic blind index: same plaintext, same prefix.
    let stored2 = direct.query_one("SELECT email FROM users WHERE id = 2", &[]).await.unwrap();
    let email2: Vec<u8> = stored2.get(0);
    assert_ne!(email[..32], email2[..32], "different plaintexts, different indexes");

    // A second insert of alice's email shares her index prefix.
    client
        .execute("INSERT INTO users (email) VALUES ($1)", &[&&b"alice@example.com"[..]])
        .await
        .unwrap();
    let stored3 = direct.query_one("SELECT email FROM users WHERE id = 3", &[]).await.unwrap();
    let email3: Vec<u8> = stored3.get(0);
    assert_eq!(email[..32], email3[..32], "equal plaintexts share the blind index");
}
