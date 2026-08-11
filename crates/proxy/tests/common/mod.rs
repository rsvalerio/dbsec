//! Shared plumbing for the end-to-end suites (milestone 10): certificates,
//! keyfile, proxy process and connection helpers.
//!
//! Every suite runs the real `dbsec` binary against a real PostgreSQL, so the
//! only thing that varies between them is the client driver and the key
//! source. Each suite owns its own listen port and table name so the binaries
//! never collide when run together.
//!
//! `DBSEC_E2E_DSN` points at a superuser DSN, default
//! `postgres://dbsec:dbsec@127.0.0.1:5433/dbsec`.

// Each test binary uses a subset of these helpers.
#![allow(dead_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};

pub const DEFAULT_DSN: &str = "postgres://dbsec:dbsec@127.0.0.1:5433/dbsec";

/// Listen ports, one per test binary — the suites must not fight over one.
pub const PORT_TOKIO_POSTGRES: u16 = 16432;
pub const PORT_SQLX: u16 = 16433;
pub const PORT_PSYCOPG: u16 = 16434;
pub const PORT_VAULT: u16 = 16435;

pub fn dsn() -> String {
    std::env::var("DBSEC_E2E_DSN").unwrap_or_else(|_| DEFAULT_DSN.to_owned())
}

/// Host:port of the database, extracted from the DSN.
pub fn upstream_addr() -> String {
    let dsn = dsn();
    let rest = dsn.split('@').nth(1).expect("dsn has host part");
    rest.split('/').next().unwrap().to_owned()
}

/// `user:password` from the DSN, reused for the proxy hop.
pub fn credentials() -> String {
    let dsn = dsn();
    dsn.split("//").nth(1).unwrap().split('@').next().unwrap().to_owned()
}

/// Database name from the DSN, ignoring any query string.
pub fn database() -> String {
    let dsn = dsn();
    let after_host = dsn.split('@').nth(1).expect("dsn has host part");
    let name = after_host.split('/').nth(1).unwrap_or("postgres");
    name.split('?').next().unwrap().to_owned()
}

/// Client DSN for the proxy's TLS listener. `localhost` (not `127.0.0.1`) so
/// the self-signed certificate's SAN matches under verify-full.
pub fn proxy_dsn(port: u16) -> String {
    format!("postgres://{}@localhost:{port}/{}?sslmode=require", credentials(), database())
}

/// Deterministic keys for a table's searchable/pseudonymized columns. Key
/// names are `schema.table.column`, so they follow the table name.
pub fn keyfile(table: &str) -> String {
    format!(
        "\
active = \"00112233445566778899aabbccddeeff\"

[keys]
00112233445566778899aabbccddeeff = \"0707070707070707070707070707070707070707070707070707070707070707\"

[index_keys]
\"public.{table}.email\" = \"0303030303030303030303030303030303030303030303030303030303030303\"
\"public.{table}.phone\" = \"0404040404040404040404040404040404040404040404040404040404040404\"
\"public.{table}.ssn\" = \"0505050505050505050505050505050505050505050505050505050505050505\"
"
    )
}

/// Which key source the proxy is configured with.
pub enum Keys {
    /// `FileKeySource` over a keyfile written into the temp dir.
    File,
    /// A verbatim `[vault]` section (milestone 9's OpenBao source).
    Vault(String),
}

pub struct ProxyOpts<'a> {
    pub port: u16,
    pub table: &'a str,
    pub keys: Keys,
}

impl<'a> ProxyOpts<'a> {
    pub fn file_keys(port: u16, table: &'a str) -> Self {
        Self { port, table, keys: Keys::File }
    }
}

/// The proxy process, killed and reaped on drop.
pub struct Proxy(std::process::Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Proxy {
    /// Stops the proxy and waits for the port to go away, so the next proxy
    /// on the same port does not inherit this one's listener.
    pub async fn shutdown(mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

pub fn cert_path(dir: &Path) -> PathBuf {
    dir.join("cert.pem")
}

/// Writes certs/keyfile/config into `dir` and launches the dbsec binary with
/// the standard protected-column set (searchable encrypt, FPE, token,
/// mask-only) over `opts.table`.
pub async fn spawn_proxy(dir: &Path, opts: &ProxyOpts<'_>) -> Proxy {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(cert_path(dir), cert.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), cert.key_pair.serialize_pem()).unwrap();

    let key_source = match &opts.keys {
        Keys::File => {
            let path = dir.join("keys.toml");
            std::fs::write(&path, keyfile(opts.table)).unwrap();
            format!("keys_file = {path:?}")
        }
        Keys::Vault(section) => section.clone(),
    };

    let config = format!(
        r#"
listen = "127.0.0.1:{port}"
upstream = "{upstream}"
control_dsn = "{dsn}"
{key_source}

[tls.downstream]
cert = {cert:?}
key = {key:?}

[[column]]
table = "{table}"
column = "email"
searchable = true

[[column]]
table = "{table}"
column = "phone"
transform = "fpe"

[[column]]
table = "{table}"
column = "ssn"
transform = "token"

[[column]]
table = "{table}"
column = "note"
transform = "none"
mask = {{ keep_first = 2 }}
"#,
        port = opts.port,
        table = opts.table,
        upstream = upstream_addr(),
        dsn = dsn(),
        cert = cert_path(dir),
        key = dir.join("key.pem"),
    );
    let config_path = dir.join("dbsec.toml");
    std::fs::File::create(&config_path).unwrap().write_all(config.as_bytes()).unwrap();

    spawn_with_config(&config_path, opts.port).await
}

/// Launches the binary against an already-written config and waits for its
/// listener. Wrapped immediately so the child is killed and reaped even when
/// the readiness loop panics.
pub async fn spawn_with_config(config_path: &Path, port: u16) -> Proxy {
    let proxy = Proxy(
        std::process::Command::new(env!("CARGO_BIN_EXE_dbsec")).arg(config_path).spawn().unwrap(),
    );
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return proxy;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("proxy did not start listening on {port}");
}

/// Client-hop TLS config trusting the proxy's self-signed cert.
pub fn client_tls(cert_pem: &str) -> tokio_postgres_rustls::MakeRustlsConnect {
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

/// Connection straight to the database, bypassing the proxy — this is what
/// sees the ciphertext at rest.
pub async fn connect_direct() -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(&dsn(), tokio_postgres::NoTls)
        .await
        .expect("is the e2e database up? run `make e2e`");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

pub async fn connect_via_proxy(dir: &Path, port: u16) -> tokio_postgres::Client {
    let cert_pem = std::fs::read_to_string(cert_path(dir)).unwrap();
    let (client, connection) =
        tokio_postgres::connect(&proxy_dsn(port), client_tls(&cert_pem)).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

/// The schema every suite protects: a BYTEA searchable column plus text
/// columns for FPE, tokens and mask-only.
pub async fn create_table(client: &tokio_postgres::Client, table: &str) {
    client
        .batch_execute(&format!(
            "DROP TABLE IF EXISTS {table};
             CREATE TABLE {table} (
                 id SERIAL PRIMARY KEY,
                 email BYTEA,
                 phone TEXT,
                 ssn TEXT,
                 note TEXT
             )"
        ))
        .await
        .unwrap();
}
