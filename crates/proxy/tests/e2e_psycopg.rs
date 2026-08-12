//! Driver matrix (milestone 10): the psycopg family through the proxy.
//!
//! The assertions live in `tests/psycopg_matrix.py` — this suite provisions
//! the schema, launches the proxy and runs that script against it, so the
//! Python drivers are covered by the same `make e2e` as the Rust ones.
//!
//! Without psycopg installed the case is skipped with a warning; set
//! `DBSEC_E2E_STRICT_DRIVERS=1` (as CI does) to make a missing driver a
//! failure rather than a silent gap in the matrix.
//!
//! Ignored by default — `make e2e` starts the database and runs it.

mod common;

use std::path::PathBuf;
use std::process::Command;

use common::port_psycopg;

const TABLE: &str = "users_psycopg";

fn script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/psycopg_matrix.py")
}

/// Whether both drivers import, so the suite can skip rather than fail on a
/// machine without them.
fn drivers_available() -> bool {
    Command::new("python3")
        .args(["-c", "import psycopg, psycopg2"])
        .output()
        .is_ok_and(|out| out.status.success())
}

#[tokio::test]
#[ignore = "needs the Postgres from `make e2e`"]
async fn psycopg_driver_matrix() {
    if !drivers_available() {
        let missing = "psycopg/psycopg2 not installed \
                       (pip install 'psycopg[binary]' psycopg2-binary)";
        assert!(
            std::env::var_os("DBSEC_E2E_STRICT_DRIVERS").is_none(),
            "{missing}, and DBSEC_E2E_STRICT_DRIVERS forbids skipping the matrix"
        );
        eprintln!("warning: {missing} — skipping the Python driver matrix");
        return;
    }

    let direct = common::connect_direct().await;
    common::create_table(&direct, TABLE).await;

    let dir = tempfile::tempdir().unwrap();
    let port = port_psycopg();
    let _proxy = common::spawn_proxy(dir.path(), &common::ProxyOpts::file_keys(port, TABLE)).await;

    // libpq conninfo rather than a URL: verify-full needs the proxy's
    // self-signed certificate as the only trusted root.
    let credentials = common::credentials();
    let (user, password) = credentials.split_once(':').expect("dsn has user:password");
    let conninfo = format!(
        "host=localhost port={port} user={user} password={password} dbname={} \
         sslmode=verify-full sslrootcert={}",
        common::database(),
        common::cert_path(dir.path()).display(),
    );

    let output = Command::new("python3")
        .arg(script())
        .env("DBSEC_PROXY_CONNINFO", conninfo)
        .env("DBSEC_DIRECT_DSN", common::dsn())
        .env("DBSEC_TABLE", TABLE)
        .output()
        .expect("running python3");

    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success(), "psycopg matrix failed: {}", output.status);
}
