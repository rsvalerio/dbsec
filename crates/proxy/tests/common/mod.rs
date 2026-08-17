//! Shared plumbing for the end-to-end suites (milestone 10): certificates,
//! keyfile, proxy process and connection helpers.
//!
//! Every suite runs the real `dbsec` binary against a real PostgreSQL, so the
//! only thing that varies between them is the client driver and the key
//! source. Each suite owns its own listen port and table name so the binaries
//! never collide when run together.
//!
//! `DBSEC_E2E_DSN` points at a superuser DSN, default
//! `postgres://dbsec:dbsec@127.0.0.1:5433/dbsec`. `DBSEC_E2E_PORT_BASE` moves
//! the block of listen ports the suites use.

// Each test binary uses a subset of these helpers.
#![allow(dead_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_DSN: &str = "postgres://dbsec:dbsec@127.0.0.1:5433/dbsec";

/// First port of the block the suites listen on, one port per test binary.
pub const DEFAULT_PORT_BASE: u16 = 16432;

/// How long `Proxy::shutdown` waits for a killed proxy's listener to go away.
const PORT_RELEASE_TIMEOUT: Duration = Duration::from_secs(10);

/// Listen port for one test binary — the suites must not fight over one, and
/// the whole block moves with `DBSEC_E2E_PORT_BASE`. Nothing stops another
/// process on the machine (a second checkout, a parallel CI job, a developer's
/// own service) from holding the default block, so it has to be movable
/// without editing the source.
fn port_at(offset: u16) -> u16 {
    let base = match std::env::var("DBSEC_E2E_PORT_BASE") {
        Ok(raw) => raw
            .parse::<u16>()
            .unwrap_or_else(|e| panic!("DBSEC_E2E_PORT_BASE={raw:?} is not a port number: {e}")),
        Err(_) => DEFAULT_PORT_BASE,
    };
    base.checked_add(offset)
        .unwrap_or_else(|| panic!("DBSEC_E2E_PORT_BASE={base} leaves no room for offset {offset}"))
}

pub fn port_tokio_postgres() -> u16 {
    port_at(0)
}

pub fn port_sqlx() -> u16 {
    port_at(1)
}

pub fn port_psycopg() -> u16 {
    port_at(2)
}

pub fn port_vault() -> u16 {
    port_at(3)
}

/// The `COPY` case runs alongside the tokio-postgres suite in the same binary,
/// so it needs its own port (and its own table) rather than its own binary.
pub fn port_copy() -> u16 {
    port_at(4)
}

/// The prepared-statement-cache case, which needs a table nothing else is
/// dropping under it.
pub fn port_prepared() -> u16 {
    port_at(5)
}

/// The schema-drift case: it recreates its table mid-test, so it cannot share
/// one with any other suite.
pub fn port_recreate() -> u16 {
    port_at(6)
}

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
    /// `on_unprotected = "reject"`: refuse statements the rewrite cannot cover
    /// instead of relaying them with a warning.
    pub strict: bool,
}

impl<'a> ProxyOpts<'a> {
    pub fn file_keys(port: u16, table: &'a str) -> Self {
        Self { port, table, keys: Keys::File, strict: false }
    }

    pub fn strict(mut self) -> Self {
        self.strict = true;
        self
    }
}

/// The proxy process, killed and reaped on drop.
pub struct Proxy {
    child: std::process::Child,
    port: u16,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Proxy {
    /// Stops the proxy and waits until its port actually refuses connections,
    /// so the next proxy on the same port does not inherit this one's listener.
    ///
    /// The wait is a poll rather than a sleep: how fast the kernel tears the
    /// listening socket down is not something the test can assume, and getting
    /// it wrong surfaces as the *next* proxy's readiness loop connecting to
    /// this one's dying socket, which reads as an unrelated failure.
    pub async fn shutdown(mut self) {
        let port = self.port;
        let _ = self.child.kill();
        let _ = self.child.wait();

        let deadline = tokio::time::Instant::now() + PORT_RELEASE_TIMEOUT;
        while tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "port {port} still accepted connections {PORT_RELEASE_TIMEOUT:?} after the proxy \
                 was killed — something else is listening on it",
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
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
    let key = dir.join("key.pem");
    std::fs::write(&key, cert.key_pair.serialize_pem()).unwrap();
    // The downstream TLS key is a secret file the proxy refuses when anyone
    // but its owner can read it (SEC-29), and `fs::write` inherits the umask.
    #[cfg(unix)]
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();

    let key_source = match &opts.keys {
        Keys::File => {
            let path = dir.join("keys.toml");
            std::fs::write(&path, keyfile(opts.table)).unwrap();
            // The proxy refuses a keyfile anyone but its owner can read
            // (SEC-29), and `fs::write` inherits the umask — so the fixture
            // has to set the mode the same way a deployment would.
            #[cfg(unix)]
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                .unwrap();
            format!("keys_file = {path:?}")
        }
        Keys::Vault(section) => section.clone(),
    };

    // `key_source` goes last of the top-level keys: in Vault mode it is a
    // whole `[vault]` table, so any bare key written after it would land
    // inside that table rather than at the document root and be rejected as
    // an unknown `[vault]` field.
    let config = format!(
        r#"
listen = "127.0.0.1:{port}"
upstream = "{upstream}"
control_dsn = "{dsn}"
{on_unprotected}
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
        on_unprotected =
            if opts.strict { "on_unprotected = \"reject\"" } else { "on_unprotected = \"warn\"" },
        upstream = upstream_addr(),
        dsn = dsn(),
        cert = cert_path(dir),
        key = dir.join("key.pem"),
    );
    let config_path = dir.join("dbsec.toml");
    std::fs::File::create(&config_path).unwrap().write_all(config.as_bytes()).unwrap();
    // This config carries a `control_dsn` password — and in Vault mode an
    // inline token — so the proxy holds it to the same mode as the keyfile
    // beside it (SEC-29), and `File::create` inherits the umask.
    #[cfg(unix)]
    std::fs::set_permissions(&config_path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .unwrap();

    spawn_with_config(&config_path, opts.port).await
}

/// Launches the binary against an already-written config and waits for its
/// listener. Wrapped immediately so the child is killed and reaped even when
/// the readiness loop panics.
pub async fn spawn_with_config(config_path: &Path, port: u16) -> Proxy {
    // Checked before spawning, because an occupied port otherwise makes the
    // readiness loop below succeed against *someone else's* listener and the
    // failure appears much later as an unrelated protocol error.
    if let Err(err) = std::net::TcpListener::bind(("127.0.0.1", port)) {
        panic!(
            "e2e port {port} is already in use ({err}) — another checkout, a parallel CI job or a \
             leftover proxy is holding it. Set DBSEC_E2E_PORT_BASE to move the suites' ports.",
        );
    }

    let proxy = Proxy {
        child: std::process::Command::new(env!("CARGO_BIN_EXE_dbsec"))
            .arg(config_path)
            .spawn()
            .unwrap(),
        port,
    };
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return proxy;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
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
