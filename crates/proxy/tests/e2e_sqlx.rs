//! Driver matrix (milestone 10): sqlx through the proxy over TLS.
//!
//! sqlx exercises wire behaviour tokio-postgres does not: it caches named
//! prepared statements per connection, so a repeated query arrives as a bare
//! Bind with no preceding Parse, and its simple-protocol path (`raw_sql`)
//! decodes text-format BYTEA (`\x` hex) rather than handing back strings.
//! Connections are verify-full against the proxy's certificate.
//!
//! Ignored by default — `make e2e` starts the database and runs it.

mod common;

use common::port_sqlx as port;
use sqlx::{Connection as _, Row as _};

/// The table name as a literal so SQL can be assembled with `concat!`: sqlx
/// 0.9 only accepts `&'static str`, rejecting formatted strings outright.
macro_rules! table {
    () => {
        "users_sqlx"
    };
}

const TABLE: &str = table!();

/// verify-full connection to the proxy, trusting only its self-signed cert.
async fn connect_sqlx(dir: &std::path::Path) -> sqlx::PgConnection {
    let credentials = common::credentials();
    let (user, password) = credentials.split_once(':').expect("dsn has user:password");
    let options = sqlx::postgres::PgConnectOptions::new()
        .host("localhost")
        .port(port())
        .username(user)
        .password(password)
        .database(&common::database())
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(common::cert_path(dir));
    sqlx::PgConnection::connect_with(&options).await.expect("sqlx connects to the proxy over TLS")
}

#[tokio::test]
#[ignore = "needs the Postgres from `make e2e`"]
async fn sqlx_driver_end_to_end() {
    let direct = common::connect_direct().await;
    common::create_table(&direct, TABLE).await;

    let dir = tempfile::tempdir().unwrap();
    let _proxy =
        common::spawn_proxy(dir.path(), &common::ProxyOpts::file_keys(port(), TABLE)).await;
    let mut conn = connect_sqlx(dir.path()).await;

    // Extended protocol. The same SQL text runs twice: sqlx parses it once
    // and the second execution is a Bind against the cached statement, so the
    // proxy's per-session statement map has to still know its parameters.
    let insert =
        concat!("INSERT INTO ", table!(), " (email, phone, ssn, note) VALUES ($1, $2, $3, $4)");
    for (email, phone, ssn, note) in [
        ("dana@example.com", "555-321-7654", "078-05-1120", "dana-note"),
        ("erin@example.com", "555-222-3333", "219-09-9999", "erin-note"),
    ] {
        sqlx::query(insert)
            .bind(email.as_bytes())
            .bind(phone)
            .bind(ssn)
            .bind(note)
            .execute(&mut conn)
            .await
            .unwrap();
    }

    // Simple protocol: literals sealed by the SQL rewrite.
    sqlx::raw_sql(concat!(
        "INSERT INTO ",
        table!(),
        " (email, phone, ssn, note)
         VALUES ('frank@example.com', '555-444-5555', '111-22-3333', 'frank-note')"
    ))
    .execute(&mut conn)
    .await
    .unwrap();

    // Reads: binary result format, decoded by sqlx.
    let rows =
        sqlx::query(concat!("SELECT email, phone, ssn, note FROM ", table!(), " ORDER BY id"))
            .fetch_all(&mut conn)
            .await
            .unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].get::<Vec<u8>, _>(0), b"dana@example.com");
    assert_eq!(rows[0].get::<String, _>(1), "555-321-7654"); // FPE detokenized
    assert_eq!(rows[0].get::<String, _>(2).len(), 64); // irreversible token
    assert_eq!(rows[0].get::<String, _>(3), "da*******"); // masked
    assert_eq!(rows[2].get::<Vec<u8>, _>(0), b"frank@example.com");
    assert_eq!(rows[2].get::<String, _>(1), "555-444-5555");

    // Reads over the simple protocol: everything comes back text-format, so
    // the BYTEA column is decoded from `\x` hex after the proxy decrypts it.
    let rows = sqlx::raw_sql(concat!("SELECT email, note FROM ", table!(), " ORDER BY id LIMIT 1"))
        .fetch_all(&mut conn)
        .await
        .unwrap();
    assert_eq!(rows[0].get::<Vec<u8>, _>(0), b"dana@example.com");
    assert_eq!(rows[0].get::<String, _>(1), "da*******");

    // Searchable equality, bound parameter and inline literal.
    let hits = sqlx::query(concat!("SELECT id FROM ", table!(), " WHERE email = $1"))
        .bind(&b"erin@example.com"[..])
        .fetch_all(&mut conn)
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    let hits =
        sqlx::raw_sql(concat!("SELECT id FROM ", table!(), " WHERE email = 'frank@example.com'"))
            .fetch_all(&mut conn)
            .await
            .unwrap();
    assert_eq!(hits.len(), 1);
    let misses = sqlx::query(concat!("SELECT id FROM ", table!(), " WHERE email = $1"))
        .bind(&b"nobody@example.com"[..])
        .fetch_all(&mut conn)
        .await
        .unwrap();
    assert!(misses.is_empty());

    // `= ANY($1)`: sqlx's multi-value lookup binds the whole list as one
    // bytea[] parameter, so the proxy has to index it element by element at
    // Bind time rather than rewriting a list of placeholders.
    let hits = sqlx::query(concat!("SELECT email FROM ", table!(), " WHERE email = ANY($1)"))
        .bind(vec![b"erin@example.com".to_vec(), b"frank@example.com".to_vec()])
        .fetch_all(&mut conn)
        .await
        .unwrap();
    let found: Vec<Vec<u8>> = hits.iter().map(|row| row.get::<Vec<u8>, _>(0)).collect();
    assert_eq!(found.len(), 2, "both bound values match");
    assert!(found.contains(&b"erin@example.com".to_vec()), "{found:?}");
    assert!(found.contains(&b"frank@example.com".to_vec()), "{found:?}");
    // A value nobody has matches nothing, rather than everything.
    let misses = sqlx::query(concat!("SELECT id FROM ", table!(), " WHERE email = ANY($1)"))
        .bind(vec![b"nobody@example.com".to_vec()])
        .fetch_all(&mut conn)
        .await
        .unwrap();
    assert!(misses.is_empty());

    // UPDATE: the assignment is sealed and the WHERE equality indexed in one
    // statement, both through bound parameters.
    let updated = sqlx::query(concat!("UPDATE ", table!(), " SET phone = $1 WHERE email = $2"))
        .bind("555-777-8888")
        .bind(&b"erin@example.com"[..])
        .execute(&mut conn)
        .await
        .unwrap();
    assert_eq!(updated.rows_affected(), 1);
    let phone: String = sqlx::query(concat!("SELECT phone FROM ", table!(), " WHERE email = $1"))
        .bind(&b"erin@example.com"[..])
        .fetch_one(&mut conn)
        .await
        .unwrap()
        .get(0);
    assert_eq!(phone, "555-777-8888");

    // At rest: sealed regardless of which driver wrote the row.
    let stored = direct
        .query(&format!("SELECT email, phone, ssn, note FROM {TABLE} ORDER BY id"), &[])
        .await
        .unwrap();
    for row in &stored {
        let email: Vec<u8> = row.get(0);
        assert_eq!(&email[32..36], b"DBS1", "blind index then envelope magic");
        assert_eq!(row.get::<_, &str>(1).len(), 12, "FPE keeps the shape");
        assert_eq!(row.get::<_, &str>(2).len(), 64, "HMAC token at rest");
    }
    assert_ne!(stored[0].get::<_, &str>(1), "555-321-7654");
    assert_eq!(stored[0].get::<_, &str>(3), "dana-note", "mask-only stays plaintext at rest");
    // The updated row's new phone is sealed too, not written through.
    assert_ne!(stored[1].get::<_, &str>(1), "555-777-8888");

    conn.close().await.unwrap();
}
