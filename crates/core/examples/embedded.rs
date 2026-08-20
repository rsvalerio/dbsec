//! dbsec-core embedded in a plain sqlx application — no proxy process.
//!
//! The policy is declared once, on the struct. `#[derive(Protect)]` generates
//! the sealed twin (`UserSealed`, here with `sqlx::FromRow`), `User::policy()`,
//! `seal`, `open`, the blind-index `email_term`, and `masked`. Everything it
//! stores is the same envelope the `dbsec` proxy writes, so the two can share
//! a table.
//!
//! Needs a PostgreSQL at `DBSEC_E2E_DSN` (default
//! `postgres://dbsec:dbsec@127.0.0.1:5433/dbsec`, the one `make e2e` starts):
//!
//! ```sh
//! cargo run -p dbsec-core --features derive --example embedded
//! ```
//!
//! Exits non-zero on any mismatch, which is what lets `make e2e` run it.

use std::sync::Arc;

use dbsec_core::keys::FileKeySource;
use dbsec_core::protector::Protector;
use dbsec_core::Protect;
use sqlx::Connection as _;

/// One declaration: which table, which column names the row, and per field
/// how it is protected. Column names default to the field names.
#[derive(Protect, Clone, Debug, PartialEq)]
#[dbsec(table = "embedded_users", row_key = "id", sealed_derive(Debug, sqlx::FromRow))]
struct User {
    id: i64,
    #[dbsec(searchable)]
    email: String,
    #[dbsec(fpe, mask(keep_last = 4))]
    phone: String,
    display_name: String,
}

/// Dev keys. In a deployment the keyfile is generated once
/// (`FileKeySource::generate`) and the deterministic keys are named after the
/// columns they serve — `schema.table.column` — or a KMS-backed `KeySource`
/// replaces the file altogether.
const KEYFILE: &str = "\
active = \"00112233445566778899aabbccddeeff\"

[keys]
00112233445566778899aabbccddeeff = \"0707070707070707070707070707070707070707070707070707070707070707\"

[index_keys]
\"public.embedded_users.email\" = \"0303030303030303030303030303030303030303030303030303030303030303\"
\"public.embedded_users.phone\" = \"0404040404040404040404040404040404040404040404040404040404040404\"
";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Keys, then one protector over the struct's own policy. `new`
    //    validates the policy up front.
    let dir = tempfile::tempdir()?;
    let keyfile = dir.path().join("keys.toml");
    std::fs::write(&keyfile, KEYFILE)?;
    let keys = Arc::new(FileKeySource::load(&keyfile)?);
    let protector = Protector::new(User::policy(), keys)?;

    // 2. A plain sqlx connection straight to the database.
    let dsn = std::env::var("DBSEC_E2E_DSN")
        .unwrap_or_else(|_| "postgres://dbsec:dbsec@127.0.0.1:5433/dbsec".to_owned());
    let mut conn = sqlx::PgConnection::connect(&dsn).await?;
    sqlx::raw_sql(
        "DROP TABLE IF EXISTS embedded_users;
         CREATE TABLE embedded_users (
             id BIGINT PRIMARY KEY, email BYTEA, phone TEXT, display_name TEXT
         )",
    )
    .execute(&mut conn)
    .await?;

    // 3. Write: seal the record, bind the sealed fields.
    let users = [
        User {
            id: 1,
            email: "alice@example.com".into(),
            phone: "555-123-4567".into(),
            display_name: "Alice".into(),
        },
        User {
            id: 2,
            email: "bob@example.com".into(),
            phone: "555-999-8888".into(),
            display_name: "Bob".into(),
        },
    ];
    for user in &users {
        let sealed = user.seal(&protector)?;
        sqlx::query(
            "INSERT INTO embedded_users (id, email, phone, display_name) VALUES ($1, $2, $3, $4)",
        )
        .bind(sealed.id)
        .bind(&sealed.email)
        .bind(&sealed.phone)
        .bind(&sealed.display_name)
        .execute(&mut conn)
        .await?;
    }

    // At rest: a blind index, then a row-bound envelope; a phone that still
    // looks like a phone number.
    let at_rest: UserSealed =
        sqlx::query_as("SELECT * FROM embedded_users WHERE id = 1").fetch_one(&mut conn).await?;
    assert_eq!(&at_rest.email[32..36], b"DBS3", "blind index, then a row-bound envelope");
    assert_ne!(at_rest.phone, "555-123-4567");
    assert_eq!(at_rest.phone.len(), "555-123-4567".len(), "FPE keeps the shape");
    println!(
        "at rest: email = {} bytes of ciphertext, phone = {}",
        at_rest.email.len(),
        at_rest.phone
    );

    // 4. Search by equality: the generated term is the stored blind-index
    //    prefix. Same predicate the proxy rewrites `email = $1` to.
    let term = User::email_term(&protector, b"bob@example.com")?;
    let found: Vec<UserSealed> =
        sqlx::query_as("SELECT * FROM embedded_users WHERE substring(email from 1 for 32) = $1")
            .bind(term)
            .fetch_all(&mut conn)
            .await?;
    let ids: Vec<i64> = found.iter().map(|u| u.id).collect();
    assert_eq!(ids, vec![2], "blind-index search finds exactly bob");
    println!("search: bob@example.com -> id {ids:?}");

    // 5. Read: rows come back as the sealed twin; `open` gives the record,
    //    `masked` the display copy.
    let rows: Vec<UserSealed> =
        sqlx::query_as("SELECT * FROM embedded_users ORDER BY id").fetch_all(&mut conn).await?;
    let mut opened = Vec::new();
    for sealed in rows {
        let user = sealed.open(&protector)?;
        let shown = user.masked(&protector)?;
        println!("row {}: {} / {} ({})", user.id, user.email, shown.phone, user.display_name);
        opened.push((user, shown.phone));
    }
    assert_eq!(
        opened,
        vec![
            (users[0].clone(), "********4567".to_owned()),
            (users[1].clone(), "********8888".to_owned()),
        ]
    );

    // 6. And the property row binding buys: the same ciphertext under another
    //    row does not open.
    let mut moved = at_rest;
    moved.id = 2;
    assert!(
        matches!(moved.open(&protector), Err(dbsec_core::Error::Decrypt)),
        "relocated value must not open"
    );
    println!("row binding: alice's ciphertext refused under row 2");

    sqlx::raw_sql("DROP TABLE embedded_users").execute(&mut conn).await?;
    println!("ok");
    Ok(())
}
