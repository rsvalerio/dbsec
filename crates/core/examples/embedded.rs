//! dbsec-core embedded in a plain sqlx application — no proxy process.
//!
//! Declares a policy, seals on the way in, searches by blind index, opens and
//! masks on the way out. Everything it stores is the same envelope the `dbsec`
//! proxy writes, so the two can share a table.
//!
//! Needs a PostgreSQL at `DBSEC_E2E_DSN` (default
//! `postgres://dbsec:dbsec@127.0.0.1:5433/dbsec`, the one `make e2e` starts):
//!
//! ```sh
//! cargo run -p dbsec-core --example embedded
//! ```
//!
//! Exits non-zero on any mismatch, which is what lets `make e2e` run it.

use std::sync::Arc;

use dbsec_core::envelope::RowKey;
use dbsec_core::keys::FileKeySource;
use dbsec_core::mask::MaskSpec;
use dbsec_core::policy::{ColumnPolicy, Policy, TablePolicy, TransformKind};
use dbsec_core::protector::{Opened, Protector};
use sqlx::{Connection as _, Row as _};

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
    // 1. The policy: which columns, how, and which table binds to its row.
    let policy = Policy::new(
        vec![
            ColumnPolicy::new("embedded_users", "email").searchable(true),
            ColumnPolicy::new("embedded_users", "phone")
                .transform(TransformKind::Fpe)
                .mask(MaskSpec { keep_first: 0, keep_last: 4, mask_with: '*' }),
        ],
        vec![TablePolicy::new("embedded_users", "id")],
    );

    // 2. Keys, then the protector. `new` validates the policy up front.
    let dir = tempfile::tempdir()?;
    let keyfile = dir.path().join("keys.toml");
    std::fs::write(&keyfile, KEYFILE)?;
    let keys = Arc::new(FileKeySource::load(&keyfile)?);
    let protector = Protector::new(policy, keys)?;

    // 3. A plain sqlx connection straight to the database.
    let dsn = std::env::var("DBSEC_E2E_DSN")
        .unwrap_or_else(|_| "postgres://dbsec:dbsec@127.0.0.1:5433/dbsec".to_owned());
    let mut conn = sqlx::PgConnection::connect(&dsn).await?;
    sqlx::raw_sql(
        "DROP TABLE IF EXISTS embedded_users;
         CREATE TABLE embedded_users (id BIGINT PRIMARY KEY, email BYTEA, phone TEXT)",
    )
    .execute(&mut conn)
    .await?;

    // 4. Write: seal each protected value, naming its row.
    for (id, email, phone) in
        [(1i64, "alice@example.com", "555-123-4567"), (2, "bob@example.com", "555-999-8888")]
    {
        let row = RowKey::from_i64(id);
        let email = protector.seal("embedded_users.email", email.as_bytes(), Some(&row))?;
        let phone = protector.seal("embedded_users.phone", phone.as_bytes(), Some(&row))?;
        sqlx::query("INSERT INTO embedded_users (id, email, phone) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(email)
            .bind(String::from_utf8(phone)?)
            .execute(&mut conn)
            .await?;
    }

    // At rest: a blind index, then a row-bound envelope; a phone that still
    // looks like a phone number.
    let at_rest = sqlx::query("SELECT email, phone FROM embedded_users WHERE id = 1")
        .fetch_one(&mut conn)
        .await?;
    let stored_email: Vec<u8> = at_rest.get(0);
    let stored_phone: String = at_rest.get(1);
    assert_eq!(&stored_email[32..36], b"DBS3", "blind index, then a row-bound envelope");
    assert_ne!(stored_phone, "555-123-4567");
    assert_eq!(stored_phone.len(), "555-123-4567".len(), "FPE keeps the shape");
    println!("at rest: email = {} bytes of ciphertext, phone = {stored_phone}", stored_email.len());

    // 5. Search by equality: ask the protector for the term, compare it to the
    //    stored blind-index prefix. Same predicate the proxy rewrites to.
    let term = protector
        .search_term("embedded_users.email", b"bob@example.com")?
        .expect("email is searchable");
    let found =
        sqlx::query("SELECT id FROM embedded_users WHERE substring(email from 1 for 32) = $1")
            .bind(term)
            .fetch_all(&mut conn)
            .await?;
    let ids: Vec<i64> = found.iter().map(|row| row.get(0)).collect();
    assert_eq!(ids, vec![2], "blind-index search finds exactly bob");
    println!("search: bob@example.com -> id {:?}", ids);

    // 6. Read: open with the row the value came back in, then mask for display.
    let rows = sqlx::query("SELECT id, email, phone FROM embedded_users ORDER BY id")
        .fetch_all(&mut conn)
        .await?;
    let mut seen = Vec::new();
    for r in &rows {
        let id: i64 = r.get(0);
        let row = RowKey::from_i64(id);
        let email =
            match protector.open("embedded_users.email", &r.get::<Vec<u8>, _>(1), Some(&row))? {
                Opened::Value(bytes) => String::from_utf8(bytes)?,
                Opened::Unprotected(_) => panic!("every row here was sealed"),
            };
        let phone = protector
            .open("embedded_users.phone", r.get::<String, _>(2).as_bytes(), Some(&row))?
            .into_value("embedded_users.phone")?;
        let shown = protector.mask("embedded_users.phone", &phone)?;
        println!("row {id}: {email} / {}", String::from_utf8_lossy(&shown));
        seen.push((id, email, String::from_utf8(shown.into_owned())?));
    }
    assert_eq!(
        seen,
        vec![
            (1, "alice@example.com".to_owned(), "********4567".to_owned()),
            (2, "bob@example.com".to_owned(), "********8888".to_owned()),
        ]
    );

    // 7. And the property row binding buys: the same ciphertext under another
    //    row does not open.
    let moved = protector.open("embedded_users.email", &stored_email, Some(&RowKey::from_i64(2)));
    assert!(matches!(moved, Err(dbsec_core::Error::Decrypt)), "relocated value must not open");
    println!("row binding: alice's ciphertext refused under row 2");

    sqlx::raw_sql("DROP TABLE embedded_users").execute(&mut conn).await?;
    println!("ok");
    Ok(())
}
