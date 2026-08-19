//! End-to-end suite (milestone 10): the real `dbsec` binary between
//! tokio-postgres (both protocols) and a real Postgres, with TLS on the
//! client hop. The sibling suites cover the other drivers (`e2e_sqlx`,
//! `e2e_psycopg`) and the OpenBao key source (`e2e_vault`).
//!
//! Ignored by default — `make e2e` starts the database and runs it.

mod common;

use common::port_tokio_postgres as port;
use futures_util::{pin_mut, SinkExt as _, StreamExt as _};

const TABLE: &str = "users";

/// The `COPY` case gets its own table and port: `create_table` drops the table
/// first, and the two tests in this binary run concurrently.
const COPY_TABLE: &str = "users_copy";

/// The prepared-statement-cache case and the schema-drift case each recreate
/// their own table, so neither can share one with another test in this binary.
const PREPARED_TABLE: &str = "users_prepared";
const RECREATE_TABLE: &str = "users_recreate";

/// The row-binding case: its proxy is the only one with a `[[table]] row_key`,
/// so it needs a table of its own too.
const ROW_KEY_TABLE: &str = "users_row_key";

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
    assert_eq!(&email[32..36], b"DBS2", "blind index then envelope magic");
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

/// `COPY` is the one write path the SQL rewrite cannot reach: its payload
/// arrives as `CopyData` frames, not as SQL. This case pins down both halves
/// of the decision recorded in `plans/PLAN.md` — that `COPY` is refused rather
/// than encrypted — against the real binary:
///
/// - under the default `on_unprotected = "warn"`, `COPY ... FROM` stores
///   plaintext in a protected column and `COPY ... TO` hands back the stored
///   form, which for a mask-only column is the *unmasked* value;
/// - under `on_unprotected = "reject"`, both directions are refused with an
///   ErrorResponse the session survives.
#[tokio::test]
#[ignore = "needs the Postgres from `make e2e`"]
async fn copy_bypasses_the_rewrite_and_is_refused_in_strict_mode() {
    let direct = common::connect_direct().await;
    common::create_table(&direct, COPY_TABLE).await;

    let dir = tempfile::tempdir().unwrap();
    let opts = common::ProxyOpts::file_keys(common::port_copy(), COPY_TABLE);
    let proxy = common::spawn_proxy(dir.path(), &opts).await;
    let client = common::connect_via_proxy(dir.path(), common::port_copy()).await;

    // A normal INSERT through the proxy: phone is FPE'd, note is stored raw
    // and masked on the way out. This is the baseline COPY is compared to.
    client
        .execute(
            "INSERT INTO users_copy (phone, ssn, note) VALUES ($1, $2, $3)",
            &[&"555-123-4567", &"078-05-1120", &"topsecret"],
        )
        .await
        .unwrap();

    // --- COPY FROM under `warn`: the plaintext lands in the column. ---
    let sink = client.copy_in("COPY users_copy (phone, ssn, note) FROM STDIN").await.unwrap();
    pin_mut!(sink);
    sink.send(&b"555-999-8888\t219-09-9999\tbulkloaded\n"[..]).await.unwrap();
    assert_eq!(sink.finish().await.unwrap(), 1);

    let bulk = direct
        .query_one("SELECT phone, note FROM users_copy WHERE note = 'bulkloaded'", &[])
        .await
        .unwrap();
    assert_eq!(
        bulk.get::<_, &str>(0),
        "555-999-8888",
        "COPY FROM is not encrypted: the plaintext is at rest, which is why it is a refusal site"
    );

    // --- COPY TO under `warn`: the read path never sees the rows. ---
    // A normal read through the proxy masks the column...
    let rows = client.query("SELECT note FROM users_copy ORDER BY id", &[]).await.unwrap();
    assert_eq!(
        rows[0].get::<_, &str>(0),
        "to*******",
        "a mask-only column is masked on a normal read"
    );

    // ...but COPY TO bypasses DataRow interception entirely.
    let stream = client.copy_out("COPY users_copy (note) TO STDOUT").await.unwrap();
    pin_mut!(stream);
    let mut copied = Vec::new();
    while let Some(chunk) = stream.next().await {
        copied.extend_from_slice(&chunk.unwrap());
    }
    let copied = String::from_utf8(copied).unwrap();
    assert!(
        copied.contains("topsecret"),
        "COPY TO leaks the unmasked stored form, which is why it is a refusal site: {copied}"
    );

    // --- `on_unprotected = "reject"`: both directions refused. ---
    proxy.shutdown().await;
    let _strict = common::spawn_proxy(dir.path(), &opts.strict()).await;
    let client = common::connect_via_proxy(dir.path(), common::port_copy()).await;

    // `CopyInSink`/`CopyOutStream` are not `Debug`, so the Ok side cannot be
    // unwrapped away — match the error out instead.
    // `tokio_postgres::Error`'s own Display is just "db error"; the proxy's
    // text is in the ErrorResponse it wraps.
    let refusal = |error: tokio_postgres::Error| {
        let db = error.as_db_error().expect("a PostgreSQL ErrorResponse, not a dropped connection");
        assert_eq!(db.code(), &tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE);
        db.message().to_owned()
    };

    let Err(error) = client.copy_in::<_, &[u8]>("COPY users_copy (phone) FROM STDIN").await else {
        panic!("strict mode must refuse COPY FROM")
    };
    let message = refusal(error);
    assert!(message.contains("dbsec refused this statement"), "{message}");
    assert!(message.contains("COPY into protected table users_copy"), "{message}");

    let Err(error) = client.copy_out("COPY users_copy (note) TO STDOUT").await else {
        panic!("strict mode must refuse COPY TO")
    };
    let message = refusal(error);
    assert!(message.contains("COPY from protected table users_copy"), "{message}");

    // The refusal is statement-level: the session is still usable.
    let rows = client.query("SELECT id FROM users_copy ORDER BY id", &[]).await.unwrap();
    assert_eq!(rows.len(), 2);
}

/// The steady state of every driver with a prepared-statement cache, against
/// the real binary: two statements are prepared once and then re-executed with
/// Bind/Execute only. The server sends RowDescription in reply to *Describe*,
/// so those later executions carry no `'T'` frame — and a proxy that keyed
/// protected positions to "the last RowDescription on the connection" decrypted
/// one statement's rows with the other's positions, or relayed a protected
/// column as raw ciphertext with no error at all (CL-3, [[task-0044]]).
///
/// The interleaving is the point: `by_id` selects a protected column, `ids`
/// selects none, and they are executed alternately over one connection.
#[tokio::test]
#[ignore = "needs the Postgres from `make e2e`"]
async fn a_cached_prepared_statement_decrypts_with_its_own_columns() {
    let direct = common::connect_direct().await;
    common::create_table(&direct, PREPARED_TABLE).await;

    let dir = tempfile::tempdir().unwrap();
    let opts = common::ProxyOpts::file_keys(common::port_prepared(), PREPARED_TABLE);
    let _proxy = common::spawn_proxy(dir.path(), &opts).await;
    let client = common::connect_via_proxy(dir.path(), common::port_prepared()).await;

    for (email, note) in [(&b"alice@example.com"[..], "topsecret"), (&b"bob@example.com"[..], "s2")]
    {
        client
            .execute(
                &format!("INSERT INTO {PREPARED_TABLE} (email, note) VALUES ($1, $2)"),
                &[&email, &note],
            )
            .await
            .unwrap();
    }

    // Prepared once each; every `query` below reuses them, so the proxy sees
    // Bind/Execute with no Describe in front of it.
    let with_protected = client
        .prepare(&format!("SELECT id, email FROM {PREPARED_TABLE} WHERE id = $1"))
        .await
        .unwrap();
    let without_protected = client
        .prepare(&format!("SELECT id, note FROM {PREPARED_TABLE} ORDER BY id"))
        .await
        .unwrap();

    // Alternate them. Before the fix, the second round of `with_protected`
    // used `without_protected`'s positions, where nothing is protected.
    for _ in 0..3 {
        let rows = client.query(&with_protected, &[&1i32]).await.unwrap();
        assert_eq!(
            rows[0].get::<_, Vec<u8>>(1),
            b"alice@example.com",
            "a cached statement must decrypt with its own column positions"
        );

        let rows = client.query(&without_protected, &[]).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].get::<_, &str>(1),
            "to*******",
            "the other statement's own positions still apply"
        );
    }

    // The two statements interleaved inside one pipeline batch, which is where
    // "the last 'T' frame wins" is least defensible.
    let (a, b) = tokio::join!(
        client.query(&with_protected, &[&2i32]),
        client.query(&without_protected, &[])
    );
    assert_eq!(a.unwrap()[0].get::<_, Vec<u8>>(1), b"bob@example.com");
    assert_eq!(b.unwrap().len(), 2);
}

/// A migration that recreates a protected table under a running proxy. The
/// write path matches columns by name and keeps encrypting; the read path
/// matches by `(table oid, attnum)`, which the new table invalidates. Without
/// re-resolution the proxy hands the client `blind_index || envelope` bytes
/// forever, with no error (CL-3, [[task-0039]]).
///
/// Both halves of the chosen behaviour are pinned here: the session that first
/// sees the moved column triggers a re-resolution and the proxy heals itself
/// well inside the (300 s) refresh interval, and under `on_unprotected =
/// "reject"` that same session fails instead of relaying the stored form.
#[tokio::test]
#[ignore = "needs the Postgres from `make e2e`"]
async fn a_recreated_table_is_re_resolved_and_refused_in_strict_mode() {
    let direct = common::connect_direct().await;
    common::create_table(&direct, RECREATE_TABLE).await;

    let dir = tempfile::tempdir().unwrap();
    let opts = common::ProxyOpts::file_keys(common::port_recreate(), RECREATE_TABLE);
    let proxy = common::spawn_proxy(dir.path(), &opts).await;
    let client = common::connect_via_proxy(dir.path(), common::port_recreate()).await;

    let insert = format!("INSERT INTO {RECREATE_TABLE} (email) VALUES ($1)");
    let select = format!("SELECT email FROM {RECREATE_TABLE} ORDER BY id");
    client.execute(&insert, &[&&b"alice@example.com"[..]]).await.unwrap();
    let rows = client.query(&select, &[]).await.unwrap();
    assert_eq!(rows[0].get::<_, Vec<u8>>(0), b"alice@example.com");

    // The migration: same names, new OID.
    common::create_table(&direct, RECREATE_TABLE).await;

    // The write path is name-keyed, so it never stopped encrypting.
    client.execute(&insert, &[&&b"carol@example.com"[..]]).await.unwrap();
    let stored: Vec<u8> =
        direct.query_one(&select, &[]).await.unwrap().get::<_, Option<Vec<u8>>>(0).unwrap();
    assert_eq!(&stored[32..36], b"DBS2", "writes are still sealed after the migration");

    // The read path heals: the first read that cannot explain the column asks
    // for a re-resolution, and the next one decrypts again. Polled rather than
    // slept on — the round trip is the proxy's, not the test's.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let rows = client.query(&select, &[]).await.unwrap();
        if rows[0].get::<_, Vec<u8>>(0) == b"carol@example.com" {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the proxy never re-resolved the recreated table; reads are still relaying the \
             stored form"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // Strict mode: the session that notices refuses rather than relaying.
    proxy.shutdown().await;
    let _strict = common::spawn_proxy(dir.path(), &opts.strict()).await;
    let client = common::connect_via_proxy(dir.path(), common::port_recreate()).await;
    client.query(&select, &[]).await.expect("resolved at startup, so this one is fine");

    common::create_table(&direct, RECREATE_TABLE).await;
    client.execute(&insert, &[&&b"dave@example.com"[..]]).await.unwrap();
    let refusal = client
        .query(&select, &[])
        .await
        .expect_err("strict mode must refuse a result column it cannot prove is unprotected");
    // The client is told *why* — the same SQLSTATE a refused write carries,
    // not a bare connection reset it would read as a network fault
    // ([[task-0064]]).
    assert_eq!(
        refusal.code(),
        Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE),
        "the client must see a database error, not a connection reset: {refusal}"
    );
    // But the session does not survive, and that is deliberate. The refused
    // SELECT has already run upstream; anything the client pipelined behind it
    // is still executing, and closing the connection is the only thing that
    // makes the backend roll that back rather than commit it behind an error
    // saying nothing happened ([[task-0071]]).
    assert!(
        client.query_one("SELECT 1", &[]).await.is_err(),
        "a read-path refusal must end the session, not resynchronise it"
    );
}

/// Row binding across the two wire formats, against the real binary.
///
/// The write here is a simple-protocol statement — a text-binding client's
/// insert, with the row key as a literal — and the read is `query`, which
/// tokio-postgres prepares: Parse, Describe(**statement**), Bind asking for
/// binary results, Execute. The RowDescription that answers that Describe
/// carries format code zero for every column, because the protocol says a
/// statement's result formats "will always be zero" — they are chosen at Bind.
/// Canonicalising the row key with the description's format read the four
/// big-endian bytes of `1` as text, mismatched the AAD, and tore the session
/// down with no ErrorResponse (SEC-31). It has to come from the Bind.
#[tokio::test]
#[ignore = "needs the Postgres from `make e2e`"]
async fn a_row_bound_value_written_in_text_reads_back_in_binary() {
    let direct = common::connect_direct().await;
    common::create_table(&direct, ROW_KEY_TABLE).await;

    let dir = tempfile::tempdir().unwrap();
    let opts = common::ProxyOpts::file_keys(common::port_row_key(), ROW_KEY_TABLE).row_key("id");
    let _proxy = common::spawn_proxy(dir.path(), &opts).await;
    let client = common::connect_via_proxy(dir.path(), common::port_row_key()).await;

    // Text-binding write: literals sealed by the SQL rewrite, bound to row 1.
    client
        .simple_query(&format!(
            "INSERT INTO {ROW_KEY_TABLE} (id, email) VALUES (1, 'grace@example.com')"
        ))
        .await
        .unwrap();

    // At rest the value is row-bound, not merely cell-bound.
    let stored: Vec<u8> = direct
        .query_one(&format!("SELECT email FROM {ROW_KEY_TABLE} WHERE id = 1"), &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(&stored[32..36], b"DBS3", "blind index then the row-bound envelope magic");

    // Binary-binding read of the same row, through a prepared statement.
    let row = client
        .query_one(&format!("SELECT id, email FROM {ROW_KEY_TABLE} WHERE id = $1"), &[&1i32])
        .await
        .expect("a binary-binding driver must be able to read a row-bound value");
    assert_eq!(row.get::<_, Vec<u8>>(1), b"grace@example.com");

    // And the session is still usable, which is what fails when the row key is
    // canonicalised in the wrong format.
    client.query_one("SELECT 1", &[]).await.unwrap();
}
