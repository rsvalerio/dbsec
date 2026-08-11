//! End-to-end suite (milestone 10): the real `dbsec` binary between a real
//! PostgreSQL driver (tokio-postgres, both protocols) and a dockerized
//! Postgres, with TLS on the client hop.
//!
//! Ignored by default — `make e2e` starts the database and runs it:
//! `DBSEC_E2E_DSN` points at a superuser DSN, default
//! `postgres://dbsec:dbsec@127.0.0.1:5433/dbsec`.

use std::io::Write as _;

const PROXY_PORT: u16 = 16432;

const KEYFILE: &str = "\
active = \"00112233445566778899aabbccddeeff\"

[keys]
00112233445566778899aabbccddeeff = \"0707070707070707070707070707070707070707070707070707070707070707\"

[index_keys]
\"public.users.email\" = \"0303030303030303030303030303030303030303030303030303030303030303\"
\"public.users.phone\" = \"0404040404040404040404040404040404040404040404040404040404040404\"
\"public.users.ssn\" = \"0505050505050505050505050505050505050505050505050505050505050505\"
";

fn dsn() -> String {
    std::env::var("DBSEC_E2E_DSN")
        .unwrap_or_else(|_| "postgres://dbsec:dbsec@127.0.0.1:5433/dbsec".to_owned())
}

/// Client-hop TLS config trusting the proxy's self-signed cert.
fn client_tls(cert_pem: &str) -> tokio_postgres_rustls::MakeRustlsConnect {
    use rustls::pki_types::pem::PemObject;
    // Both `ring` and `aws-lc-rs` are in the dependency graph, so rustls
    // needs an explicit process-level provider (same as the proxy itself).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config =
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    tokio_postgres_rustls::MakeRustlsConnect::new(config)
}

async fn connect_direct() -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(&dsn(), tokio_postgres::NoTls)
        .await
        .expect("is the e2e database up? run `make e2e`");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

struct Proxy(std::process::Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Writes keyfile/certs/config into `dir` and launches the dbsec binary.
async fn spawn_proxy(dir: &std::path::Path) -> Proxy {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(dir.join("cert.pem"), cert.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), cert.key_pair.serialize_pem()).unwrap();
    std::fs::write(dir.join("keys.toml"), KEYFILE).unwrap();

    let config = format!(
        r#"
listen = "127.0.0.1:{PROXY_PORT}"
upstream = "{upstream}"
keys_file = {keys:?}
control_dsn = "{dsn}"

[tls.downstream]
cert = {cert:?}
key = {key:?}

[[column]]
table = "users"
column = "email"
searchable = true

[[column]]
table = "users"
column = "phone"
transform = "fpe"

[[column]]
table = "users"
column = "ssn"
transform = "token"

[[column]]
table = "users"
column = "note"
transform = "none"
mask = {{ keep_first = 2 }}
"#,
        upstream = upstream_addr(),
        dsn = dsn(),
        keys = dir.join("keys.toml"),
        cert = dir.join("cert.pem"),
        key = dir.join("key.pem"),
    );
    let config_path = dir.join("dbsec.toml");
    std::fs::File::create(&config_path).unwrap().write_all(config.as_bytes()).unwrap();

    // Wrapped immediately so the child is killed and reaped even when the
    // readiness loop below panics.
    let proxy = Proxy(
        std::process::Command::new(env!("CARGO_BIN_EXE_dbsec")).arg(&config_path).spawn().unwrap(),
    );

    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", PROXY_PORT)).await.is_ok() {
            return proxy;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("proxy did not start listening");
}

/// Host:port of the dockerized Postgres, extracted from the DSN.
fn upstream_addr() -> String {
    let dsn = dsn();
    let rest = dsn.split('@').nth(1).expect("dsn has host part");
    rest.split('/').next().unwrap().to_owned()
}

async fn connect_via_proxy(dir: &std::path::Path) -> tokio_postgres::Client {
    let cert_pem = std::fs::read_to_string(dir.join("cert.pem")).unwrap();
    let user_pass = dsn();
    let creds = user_pass.split("//").nth(1).unwrap().split('@').next().unwrap().to_owned();
    let proxy_dsn = format!("postgres://{creds}@localhost:{PROXY_PORT}/dbsec?sslmode=require");
    let (client, connection) =
        tokio_postgres::connect(&proxy_dsn, client_tls(&cert_pem)).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

#[tokio::test]
#[ignore = "needs the dockerized Postgres from `make e2e`"]
async fn transparent_encryption_end_to_end() {
    let direct = connect_direct().await;
    direct
        .batch_execute(
            "DROP TABLE IF EXISTS users;
             CREATE TABLE users (
                 id SERIAL PRIMARY KEY,
                 email BYTEA,
                 phone TEXT,
                 ssn TEXT,
                 note TEXT
             )",
        )
        .await
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let _proxy = spawn_proxy(dir.path()).await;
    let client = connect_via_proxy(dir.path()).await;

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
