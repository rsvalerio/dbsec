//! The end-to-end suite: [`QueryRewriter`] driven through whole protocol frames.
//!
//! These are deliberately not filed under `frame`, `statement`, `query` or
//! `predicate`. Each one enters through a frame and asserts on what leaves the
//! other side — extended-protocol parameter binding, COPY classification,
//! subquery and derived-table traversal, refusal plumbing, the logging audit —
//! so every one of them crosses those layers by construction. Filing each under
//! the layer it happens to touch first would put the same kind of test in four
//! different files.
//!
//! Fixtures come from [`super::test_support`].

use std::borrow::Cow;
use std::sync::atomic::Ordering;

use sqlparser::ast::Ident;

use super::array::tests::binary_array;
use super::lexer::parse_sql;
use super::test_support::*;
use super::*;
use crate::rows::tests::transform;
use crate::session::FrameAction;
use dbsec_core::blind_index;
use dbsec_pgwire as pgwire;

#[test]
fn cast_wrapped_searchable_equality_is_rewritten() {
    use crate::rows::tests::INDEX_KEY;

    let mut rewriter = rewriter(catalog(true));
    let hex = hex::encode("alice@example.com");
    let sql = rewritten_query(
        &mut rewriter,
        &format!("SELECT id FROM users WHERE email = '\\x{hex}'::bytea"),
    )
    .expect("rewritten");

    let expected = blind_index::compute(&INDEX_KEY, b"alice@example.com");
    assert!(sql.contains("SUBSTRING(email FROM 1 FOR 32)"), "{sql}");
    assert!(sql.contains(&sealed_literal(&expected)), "{sql}");
}

#[test]
fn unrelated_sql_passes_through() {
    let mut rewriter = rewriter(catalog(false));
    for sql in [
        "SELECT * FROM users",
        "INSERT INTO other (email) VALUES ('x')",
        "UPDATE other SET email = 'x'",
        "this is not SQL at all",
    ] {
        assert!(rewritten_query(&mut rewriter, sql).is_none(), "{sql}");
    }
}

#[test]
fn extended_protocol_seals_bound_params() {
    let mut rewriter = rewriter(catalog(false));

    let parse = pgwire::encode_parse(
        b"stmt1",
        b"INSERT INTO users (id, email) VALUES ($1, $2)",
        &0i16.to_be_bytes(),
    );
    assert!(matches!(rewriter.on_frame(b'P', &parse).unwrap(), FrameAction::Relay));

    // Text-format params: the protected one becomes \x hex.
    let bind = pgwire::encode_bind(
        b"",
        b"stmt1",
        &[],
        &[
            Some(Cow::Borrowed(b"1".as_slice())),
            Some(Cow::Borrowed(b"carol@example.com".as_slice())),
        ],
        &0i16.to_be_bytes(),
    )
    .unwrap();
    let FrameAction::Replace(rewritten) = rewriter.on_frame(b'B', &bind).unwrap() else {
        panic!("bind not rewritten")
    };
    let bound = pgwire::parse_bind(&rewritten).unwrap();
    assert_eq!(bound.params[0], Some(b"1".as_slice()));
    let sealed_hex = bound.params[1].unwrap();
    let stored = hex::decode(sealed_hex.strip_prefix(b"\\x").unwrap()).unwrap();
    assert_eq!(transform(false).open(&stored, None).unwrap().unwrap(), b"carol@example.com");

    // Binary-format params stay raw bytes.
    let bind = pgwire::encode_bind(
        b"",
        b"stmt1",
        &[1],
        &[
            Some(Cow::Borrowed(b"1".as_slice())),
            Some(Cow::Borrowed(b"dave@example.com".as_slice())),
        ],
        &0i16.to_be_bytes(),
    )
    .unwrap();
    let FrameAction::Replace(rewritten) = rewriter.on_frame(b'B', &bind).unwrap() else {
        panic!("bind not rewritten")
    };
    let bound = pgwire::parse_bind(&rewritten).unwrap();
    assert_eq!(
        transform(false).open(bound.params[1].unwrap(), None).unwrap().unwrap(),
        b"dave@example.com"
    );

    // Closing the statement forgets it.
    let mut close = vec![b'S'];
    close.extend_from_slice(b"stmt1\0");
    rewriter.on_frame(b'C', &close).unwrap();
    assert!(matches!(rewriter.on_frame(b'B', &bind).unwrap(), FrameAction::Relay));
}

#[test]
fn parse_with_inline_literal_is_rewritten() {
    let mut rewriter = rewriter(catalog(false));
    let parse = pgwire::encode_parse(
        b"",
        b"INSERT INTO users (email) VALUES ('eve@example.com')",
        &0i16.to_be_bytes(),
    );
    let FrameAction::Replace(rewritten) = rewriter.on_frame(b'P', &parse).unwrap() else {
        panic!("parse not rewritten")
    };
    let reparsed = pgwire::parse_parse(&rewritten).unwrap();
    let sql = std::str::from_utf8(reparsed.query).unwrap();
    assert!(!sql.contains("eve@example.com"));
    assert_eq!(open_hex_literal(sql, false), b"eve@example.com");
}

#[test]
fn searchable_equality_rewrites_to_index_prefix_match() {
    use crate::rows::tests::INDEX_KEY;

    let mut rewriter = rewriter(catalog(true));
    let sql =
        rewritten_query(&mut rewriter, "SELECT id FROM users WHERE email = 'alice@example.com'")
            .expect("rewritten");

    let expected = blind_index::compute(&INDEX_KEY, b"alice@example.com");
    assert!(!sql.contains("alice@example.com"), "{sql}");
    assert!(sql.contains("SUBSTRING(email FROM 1 FOR 32)"), "prefix match missing: {sql}");
    assert!(sql.contains(&sealed_literal(&expected)), "{sql}");

    // Aliased and AND-nested references rewrite too; DELETE works.
    let sql = rewritten_query(
        &mut rewriter,
        "DELETE FROM users u WHERE u.id > 4 AND (u.email = 'bob@x.io' OR u.email = 'c@y.io')",
    )
    .expect("rewritten");
    assert!(!sql.contains("bob@x.io") && !sql.contains("c@y.io"), "{sql}");
    assert_eq!(sql.matches("SUBSTRING(u.email FROM 1 FOR 32)").count(), 2, "{sql}");
}

#[test]
fn searchable_equality_placeholder_binds_the_index() {
    use crate::rows::tests::INDEX_KEY;

    let mut rewriter = rewriter(catalog(true));
    let parse = pgwire::encode_parse(
        b"find",
        b"SELECT id FROM users WHERE email = $1",
        &0i16.to_be_bytes(),
    );
    let FrameAction::Replace(rewritten) = rewriter.on_frame(b'P', &parse).unwrap() else {
        panic!("parse not rewritten")
    };
    let reparsed = pgwire::parse_parse(&rewritten).unwrap();
    let sql = std::str::from_utf8(reparsed.query).unwrap();
    assert!(sql.contains("SUBSTRING(email FROM 1 FOR 32) = $1"), "{sql}");

    let bind = pgwire::encode_bind(
        b"",
        b"find",
        &[],
        &[Some(Cow::Borrowed(b"alice@example.com".as_slice()))],
        &0i16.to_be_bytes(),
    )
    .unwrap();
    let FrameAction::Replace(rewritten) = rewriter.on_frame(b'B', &bind).unwrap() else {
        panic!("bind not rewritten")
    };
    let bound = pgwire::parse_bind(&rewritten).unwrap();
    let expected = blind_index::compute(&INDEX_KEY, b"alice@example.com");
    assert_eq!(bound.params[0].unwrap(), format!("\\x{}", hex::encode(expected)).as_bytes());
}

#[test]
fn non_searchable_equality_is_left_alone() {
    let mut rewriter = rewriter(catalog(false));
    for sql in [
        "SELECT id FROM users WHERE email = 'alice@example.com'",
        "SELECT id FROM other WHERE email = 'x'",
        "SELECT id FROM users WHERE id = 4",
    ] {
        assert!(rewritten_query(&mut rewriter, sql).is_none(), "{sql}");
    }
}

/// One placeholder cannot be sealed *and* blind-indexed: a Bind carries
/// one value per placeholder. Before, both actions were applied in
/// sequence and the index was computed over the ciphertext, so the WHERE
/// matched nothing and the UPDATE silently affected no rows.
///
/// The refusal is statement-level: this is valid client SQL, and killing
/// the session over it left the client with a bare connection reset — and
/// a pooled retry that took the next connection with it.
#[test]
fn a_placeholder_in_two_protected_roles_is_refused_rather_than_transformed_twice() {
    let mut extended = rewriter(catalog(true));
    let parse = pgwire::encode_parse(
        b"u",
        b"UPDATE users SET email = $1 WHERE email = $1",
        &0i16.to_be_bytes(),
    );
    let action = extended.on_frame(b'P', &parse).unwrap();
    assert!(refusal(&action).contains("placeholder $1"), "{}", refusal(&action));
    // The batch is discarded up to Sync, which the proxy answers itself,
    // and the session is usable afterwards.
    assert_eq!(extended.on_frame(b'B', b"").unwrap(), FrameAction::Reply(Vec::new()));
    let FrameAction::Reply(sync) = extended.on_frame(b'S', b"").unwrap() else {
        panic!("Sync must be answered")
    };
    assert_eq!(sync[0], b'Z');
    assert!(matches!(
        extended.on_frame(b'Q', &query_frame("SELECT 1")).unwrap(),
        FrameAction::Relay
    ));
    // The same shape in the simple protocol has two independent literals,
    // so both roles are served from the plaintext and it still works.
    let mut simple = rewriter(catalog(true));
    let sql = "UPDATE users SET email = 'alice@example.com' WHERE email = 'alice@example.com'";
    let sql = rewritten_query(&mut simple, sql).expect("rewritten");
    assert!(!sql.contains("alice@example.com"), "{sql}");
    assert!(sql.contains("SUBSTRING(email FROM 1 FOR 32)"), "{sql}");
    assert_eq!(open_hex_literal(&sql, true), b"alice@example.com");
    let index = blind_index::compute(&crate::rows::tests::INDEX_KEY, b"alice@example.com");
    assert!(sql.contains(&sealed_literal(&index)), "{sql}");
}

/// `INSERT INTO users (email, backup_email) VALUES ($1, $1)` is valid
/// client SQL that the Bind cannot carry, so it is refused at statement
/// level in both protocols — and under *both* `on_unprotected` settings,
/// because there is no "warn and relay" answer: relaying it would seal one
/// value and then re-seal or blind-index the ciphertext.
#[test]
fn one_placeholder_for_two_protected_columns_is_refused_under_both_policies() {
    const SQL: &str = "INSERT INTO users (email, backup_email) VALUES ($1, $1)";
    for policy in [OnUnprotected::Warn, OnUnprotected::Reject] {
        // Simple protocol: nothing reached the backend, so the proxy owes
        // the ReadyForQuery itself.
        let mut simple = rewriter(two_column_catalog(policy));
        let action = simple.on_frame(b'Q', &query_frame(SQL)).unwrap();
        let text = refusal(&action);
        assert!(text.contains("placeholder $1"), "{text}");
        let FrameAction::Reply(bytes) = &action else { unreachable!() };
        assert_eq!(bytes[bytes.len() - 1], b'I', "the refusal answers the batch too");
        assert!(
            matches!(simple.on_frame(b'Q', &query_frame("SELECT 1")).unwrap(), FrameAction::Relay),
            "the session stays usable"
        );

        // Extended protocol: refused at Parse, and the rest of the batch
        // is discarded up to Sync exactly as any other refused Parse is.
        let mut extended = rewriter(two_column_catalog(policy));
        let parse = pgwire::encode_parse(b"i", SQL.as_bytes(), &0i16.to_be_bytes());
        let action = extended.on_frame(b'P', &parse).unwrap();
        assert!(refusal(&action).contains("placeholder $1"));
        assert_eq!(extended.on_frame(b'E', b"").unwrap(), FrameAction::Reply(Vec::new()));
        let FrameAction::Reply(sync) = extended.on_frame(b'S', b"").unwrap() else {
            panic!("Sync must be answered")
        };
        assert_eq!(sync[0], b'Z');
    }
}

/// The same action recorded twice for one placeholder — a multi-row INSERT
/// repeating `$1` — is one transform. Applying it twice sealed an already
/// sealed value, which no read path can undo.
#[test]
fn a_placeholder_reused_for_one_column_is_sealed_once_not_twice() {
    let mut extended = rewriter(catalog(false));
    let parse = pgwire::encode_parse(
        b"i",
        b"INSERT INTO users (email) VALUES ($1), ($1)",
        &0i16.to_be_bytes(),
    );
    assert!(matches!(extended.on_frame(b'P', &parse).unwrap(), FrameAction::Relay));
    let bind = pgwire::encode_bind(
        b"",
        b"i",
        &[],
        &[Some(Cow::Borrowed(b"alice@example.com".as_slice()))],
        &0i16.to_be_bytes(),
    )
    .unwrap();
    let FrameAction::Replace(rewritten) = extended.on_frame(b'B', &bind).unwrap() else {
        panic!("bind not rewritten")
    };
    let bound = pgwire::parse_bind(&rewritten).unwrap();
    let stored = hex::decode(bound.params[0].unwrap().strip_prefix(b"\\x").unwrap()).unwrap();
    // A double seal would open to the inner ciphertext, not the plaintext.
    assert_eq!(transform(false).open(&stored, None).unwrap().unwrap(), b"alice@example.com");

    // The simple protocol seals each literal from the plaintext already.
    let mut simple = rewriter(catalog(false));
    let sql =
        rewritten_query(&mut simple, "INSERT INTO users (email) VALUES ('bob@x.io'), ('bob@x.io')")
            .expect("rewritten");
    for literal in sql.split(SEALED_PREFIX).skip(1) {
        let stored = hex::decode(&literal[..literal.find('\'').unwrap()]).unwrap();
        assert_eq!(transform(false).open(&stored, None).unwrap().unwrap(), b"bob@x.io");
    }
}

/// `$0` names no bindable parameter. It used to underflow: a panic in
/// debug builds (a remote panic on a pre-authentication path) and a
/// rewrite against `usize::MAX` in release ones.
#[test]
fn a_zero_placeholder_resolves_to_nothing_and_leaves_the_statement_alone() {
    assert_eq!(placeholder_index("$0"), None);
    assert_eq!(placeholder_index("$1"), Some(0));
    assert_eq!(placeholder_index("$"), None);
    assert_eq!(placeholder_index("$x"), None);
    assert_eq!(placeholder_index("$99999999999999999999999999"), None);

    let mut rewriter = rewriter(catalog(true));
    for sql in [
        "SELECT id FROM users WHERE email = $0",
        "INSERT INTO users (email) VALUES ($0)",
        "UPDATE users SET email = $0 WHERE id = 1",
    ] {
        assert!(rewritten_query(&mut rewriter, sql).is_none(), "{sql}");
        let parse = pgwire::encode_parse(b"", sql.as_bytes(), &0i16.to_be_bytes());
        assert!(matches!(rewriter.on_frame(b'P', &parse).unwrap(), FrameAction::Relay), "{sql}");
    }
}

/// The statement map is keyed by a client-chosen name off the wire, so a
/// client that never closes what it parses must hit a ceiling (SEC-33).
#[test]
fn parse_messages_are_refused_once_the_statement_cap_is_reached() {
    use crate::portal::{MAX_NAME_LEN, MAX_PREPARED_STATEMENTS};

    let mut rewriter = rewriter(catalog(false));
    for i in 0..MAX_PREPARED_STATEMENTS {
        let parse =
            pgwire::encode_parse(format!("s{i}").as_bytes(), b"SELECT 1", &0i16.to_be_bytes());
        rewriter.on_frame(b'P', &parse).expect("within the cap");
    }
    let parse = pgwire::encode_parse(b"one too many", b"SELECT 1", &0i16.to_be_bytes());
    assert!(matches!(rewriter.on_frame(b'P', &parse), Err(Error::SessionLimit { .. })));

    // Closing a statement makes room again.
    let mut close = vec![b'S'];
    close.extend_from_slice(b"s0\0");
    rewriter.on_frame(b'C', &close).unwrap();
    rewriter.on_frame(b'P', &parse).expect("a closed statement freed a slot");

    // The key itself is bounded: a Parse body may be up to 1 GiB.
    let long = vec![b'x'; MAX_NAME_LEN + 1];
    let parse = pgwire::encode_parse(&long, b"SELECT 1", &0i16.to_be_bytes());
    assert!(matches!(
        rewriter.on_frame(b'P', &parse),
        Err(Error::NameTooLong { max: MAX_NAME_LEN, .. })
    ));
}

#[test]
fn malformed_describe_and_close_targets_fail_the_session() {
    let mut rewriter = rewriter(catalog(false));
    for body in [b"X".as_slice(), b"", b"Sunterminated"] {
        assert!(rewriter.on_frame(b'D', body).is_err(), "{body:?}");
        assert!(rewriter.on_frame(b'C', body).is_err(), "{body:?}");
    }
    assert!(rewriter.on_frame(b'E', b"unterminated").is_err());
}

#[test]
fn null_and_unsupported_expressions_pass_through() {
    let mut rewriter = rewriter(catalog(false));
    assert!(rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES (NULL)").is_none());
    assert!(
        rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES (lower('X'))").is_none()
    );
}

// --- fail-closed mode ------------------------------------------------

/// Each passthrough site is a warning under the default and an
/// ErrorResponse under `on_unprotected = "reject"`.
#[test]
fn every_unprotected_site_passes_through_or_is_refused() {
    let sites: [(&str, &str); 8] = [
        ("INSERT INTO users VALUES (1, 'a@b.io')", "column list"),
        ("INSERT INTO users (email) SELECT email FROM other", "INSERT ... SELECT"),
        ("COPY users (email) FROM STDIN", "COPY"),
        ("INSERT INTO users (email) VALUES (lower('a@b.io'))", "unsupported value"),
        (
            "INSERT INTO users (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET email = lower('x')",
            "conflict action",
        ),
        (
            "MERGE INTO users u USING staging s ON u.id = s.id \
             WHEN MATCHED THEN UPDATE SET email = s.email",
            "MERGE",
        ),
        ("PREPARE ins AS INSERT INTO users (email) VALUES ('a@b.io')", "PREPARE"),
        ("this is not SQL at all", "unparseable"),
    ];

    let mut permissive = rewriter(catalog(false));
    for (sql, what) in sites {
        let action = permissive.on_frame(b'Q', &query_frame(sql)).unwrap();
        assert!(
            matches!(action, FrameAction::Relay),
            "{what}: expected a passthrough, got a refusal"
        );
    }

    for (sql, what) in sites {
        let mut strict = rewriter(strict_catalog(false));
        let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
        let message = refusal(&action);
        assert!(message.contains("dbsec refused this statement"), "{what}: {message}");
        let FrameAction::Reply(bytes) = &action else { unreachable!() };
        assert_eq!(bytes[bytes.len() - 6], b'Z', "{what}: ReadyForQuery follows the error");
    }
}

/// A subquery in an *expression* position carries its own FROM, so the
/// searchable equality inside it has to be rewritten against that scope.
/// The outer statement mentions no protected column at all, which is why
/// nothing signalled: the predicate simply compared plaintext against the
/// stored form and matched nothing.
#[test]
fn searchable_equality_inside_an_operand_subquery_is_rewritten() {
    for sql in [
        // Scalar subquery as an operand.
        "SELECT * FROM orders WHERE user_id = \
         (SELECT id FROM users WHERE email = 'alice@secret.test')",
        // EXISTS, which was not even an arm in the predicate walk.
        "SELECT * FROM orders o WHERE EXISTS \
         (SELECT 1 FROM users u WHERE u.email = 'alice@secret.test')",
        // The body of IN (SELECT ...).
        "SELECT * FROM orders WHERE user_id IN \
         (SELECT id FROM users WHERE email = 'alice@secret.test')",
        // Projection position.
        "SELECT (SELECT id FROM users WHERE email = 'alice@secret.test') FROM orders",
        // Nested two deep, to pin that the recursion is not one level.
        "SELECT * FROM orders WHERE user_id IN (SELECT id FROM t WHERE x IN \
         (SELECT id FROM users WHERE email = 'alice@secret.test'))",
        // Inside a function argument and a CASE.
        "SELECT coalesce((SELECT id FROM users WHERE email = 'alice@secret.test'), 0) FROM t",
        "SELECT CASE WHEN EXISTS \
         (SELECT 1 FROM users WHERE email = 'alice@secret.test') THEN 1 ELSE 0 END FROM t",
        // ORDER BY and HAVING.
        "SELECT id FROM orders ORDER BY \
         (SELECT id FROM users WHERE email = 'alice@secret.test')",
        "SELECT count(*) FROM orders HAVING count(*) > \
         (SELECT id FROM users WHERE email = 'alice@secret.test')",
    ] {
        let mut rewriter = rewriter(catalog(true));
        let rewritten = rewritten_query(&mut rewriter, sql)
            .unwrap_or_else(|| panic!("subquery was never traversed: {sql}"));
        assert!(
            rewritten.to_ascii_uppercase().contains("SUBSTRING"),
            "the inner equality was not indexed: {rewritten}"
        );
        assert!(
            !rewritten.contains("alice@secret.test"),
            "plaintext still compared against the stored form: {rewritten}"
        );
    }
}

/// The amplifier that makes "matches nothing" unsafe rather than merely
/// wrong: an empty subquery result turns `NOT IN (empty)` into true for
/// every row, so the DELETE takes the whole table instead of sparing the
/// rows the operator meant to keep.
#[test]
fn the_not_in_subquery_mass_delete_amplifier_is_rewritten() {
    let sql = "DELETE FROM t WHERE id NOT IN \
               (SELECT id FROM users WHERE email = 'keep@secret.test')";

    let mut rewriter = rewriter(catalog(true));
    let rewritten = rewritten_query(&mut rewriter, sql).expect("the subquery was traversed");
    assert!(rewritten.to_ascii_uppercase().contains("SUBSTRING"), "not indexed: {rewritten}");
    assert!(!rewritten.contains("keep@secret.test"), "plaintext survived: {rewritten}");

    // The rewritten predicate must still be a NOT IN over the same shape,
    // so the statement's meaning is unchanged apart from the index match.
    assert!(rewritten.contains("NOT IN"), "the predicate shape changed: {rewritten}");
}

/// A subquery predicate that cannot be expressed as an index match is a
/// site like any other — reaching it through a subquery must not lose the
/// signal, or `reject` would pass exactly the queries it exists to catch.
#[test]
fn an_unrewritable_predicate_inside_a_subquery_is_still_refused() {
    for sql in [
        "SELECT * FROM orders WHERE user_id = \
         (SELECT id FROM users WHERE email LIKE 'a%')",
        "SELECT * FROM orders WHERE EXISTS \
         (SELECT 1 FROM users WHERE email > 'a@b.io')",
        "SELECT (SELECT id FROM users WHERE email = lower('a@b.io')) FROM t",
    ] {
        let mut strict = rewriter(strict_catalog(true));
        let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
        assert!(
            refusal(&action).contains("searchable column email"),
            "{sql}\n  got: {}",
            refusal(&action)
        );
    }
}

/// Row-wise `(a, b) IN (...)` puts a row constructor where a column
/// reference would be, so no single transform covers it. It cannot be
/// rewritten, but relaying it silently is the same no-match failure.
#[test]
fn a_row_wise_in_list_over_a_searchable_column_is_signalled() {
    let sql = "SELECT id FROM users WHERE (email, id) IN (('a@b.io', 1), ('c@d.io', 2))";

    let mut permissive = rewriter(catalog(true));
    assert!(rewritten_query(&mut permissive, sql).is_none(), "nothing to rewrite");

    let mut strict = rewriter(strict_catalog(true));
    let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
    assert!(refusal(&action).contains("searchable column email"), "{}", refusal(&action));
}

/// The traversal must not turn subqueries over unprotected columns into
/// refusals, nor rewrite anything in them.
#[test]
fn subqueries_over_unprotected_columns_are_left_alone() {
    let mut strict = rewriter(strict_catalog(true));
    for sql in [
        "SELECT * FROM orders WHERE user_id = (SELECT id FROM other WHERE name = 'x')",
        "SELECT * FROM orders WHERE EXISTS (SELECT 1 FROM other WHERE id > 4)",
        "SELECT (SELECT id FROM other WHERE name = 'x') FROM t",
    ] {
        assert!(
            matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
            "{sql}"
        );
    }
}

/// PostgreSQL fills a RowDescription's table OID only for a direct column
/// reference, so anything wrapped around a protected column comes back as
/// `(0, 0)` and the read path cannot act on it. For a mask-only column
/// that returns the value the mask exists to hide; for an encrypted one it
/// returns the raw stored form. The statement still names the column, so
/// the decision is made here.
#[test]
fn a_protected_column_computed_over_in_the_projection_is_signalled() {
    for sql in [
        "SELECT email || '' FROM users",
        "SELECT email::text FROM users",
        "SELECT coalesce(email, '') FROM users",
        "SELECT lower(email) FROM users",
        "SELECT max(email) FROM users",
        "SELECT CASE WHEN id > 1 THEN email ELSE '' END FROM users",
        // Aliasing it back to the column's own name changes nothing.
        "SELECT email || '' AS email FROM users",
    ] {
        let mut strict = rewriter(strict_catalog(false));
        let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
        let refusal = refusal(&action);
        assert!(
            refusal.contains("projected through") && refusal.contains("email"),
            "{sql}\n  got: {refusal}"
        );
    }
}

/// The shapes that must keep working: selecting the column directly is
/// exactly what the read path handles, and expressions over other columns
/// are none of this check's business.
#[test]
fn selecting_a_protected_column_directly_is_not_a_computed_column() {
    let mut strict = rewriter(strict_catalog(false));
    for sql in [
        "SELECT email FROM users",
        "SELECT u.email FROM users u",
        "SELECT email AS e FROM users",
        "SELECT * FROM users",
        "SELECT id + 1 FROM users",
        "SELECT lower(name) FROM users",
        "SELECT count(*) FROM users",
        "SELECT lower(email) FROM other",
    ] {
        assert!(
            matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
            "{sql}"
        );
    }
}

/// A non-UTF-8 Query body never reaches the parser; it is still a site.
#[test]
fn non_utf8_query_is_refused_in_strict_mode() {
    let mut strict = rewriter(strict_catalog(false));
    let action = strict.on_frame(b'Q', &[0xff, 0xfe, 0]).unwrap();
    assert!(refusal(&action).contains("not valid UTF-8"));

    let mut permissive = rewriter(catalog(false));
    assert!(matches!(permissive.on_frame(b'Q', &[0xff, 0xfe, 0]).unwrap(), FrameAction::Relay));
}

/// On the wire a `COPY ... FROM STDIN` has no terminator and no payload —
/// the rows arrive later as `CopyData` frames — but sqlparser wants one or
/// the other. Without the retry in [`parse_sql`] the statement reads as
/// unparseable SQL and both the warning and the refusal name the wrong
/// problem.
#[test]
fn copy_is_recognised_in_both_directions_without_a_terminator() {
    let mut strict = rewriter(strict_catalog(false));
    for (sql, expected) in [
        ("COPY users (email) FROM STDIN", "COPY into protected table users"),
        ("COPY users TO STDOUT", "COPY from protected table users"),
    ] {
        let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
        assert!(refusal(&action).contains(expected), "{sql}: {}", refusal(&action));
    }

    // Genuinely unparseable SQL is still reported as such.
    let action = strict.on_frame(b'Q', &query_frame("this is not SQL at all")).unwrap();
    assert!(refusal(&action).contains("could not be parsed"), "{}", refusal(&action));
}

/// The query-source form of the same statement. `COPY (SELECT email FROM
/// users) TO STDOUT` is a `CopySource::Query`, so the classifier — which
/// looked at `CopySource::Table` only — never saw it, and its rows leave
/// as `CopyData` frames the read path relays verbatim. The table form was
/// refused under `reject` and this one was not, which is the strict
/// setting being escaped by rewriting the statement.
#[test]
fn a_query_source_copy_out_over_a_protected_table_is_a_site_in_both_modes() {
    let statements = [
        "COPY (SELECT email FROM users) TO STDOUT",
        "COPY (SELECT * FROM users WHERE id = 1) TO STDOUT",
        // The shapes a walk of the top-level FROM clause alone would miss.
        "COPY (SELECT e FROM (SELECT email AS e FROM users) s) TO STDOUT",
        "COPY (WITH c AS (SELECT email FROM users) SELECT * FROM c) TO STDOUT",
        "COPY (SELECT id FROM other UNION ALL SELECT id FROM users) TO STDOUT",
        "COPY (SELECT * FROM (other JOIN users ON other.id = users.id)) TO STDOUT",
    ];

    let mut strict = rewriter(strict_catalog(false));
    for sql in statements {
        let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
        assert!(refusal(&action).contains("protected table users"), "{sql}: {}", refusal(&action));
    }

    // `COPY (TABLE users) TO STDOUT` is the one query source sqlparser
    // 0.53 cannot parse (`parse_as_table` overruns the closing paren), so
    // it lands on the unparseable-SQL site instead — refused all the same,
    // which is what keeps the parser quirk from being a hole.
    let action = strict.on_frame(b'Q', &query_frame("COPY (TABLE users) TO STDOUT")).unwrap();
    assert!(refusal(&action).contains("could not be parsed"), "{}", refusal(&action));

    // Under warn the same statements relay, each with one warning naming
    // the table — and a query over nothing protected stays silent.
    let (_, events) = crate::captured_events(|| {
        let mut permissive = rewriter(catalog(false));
        for sql in statements.iter().chain(&["COPY (SELECT id FROM other) TO STDOUT"]) {
            assert!(
                matches!(permissive.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
                "{sql}"
            );
        }
    });
    assert_eq!(events.len(), statements.len(), "one warning each: {events:?}");
    for event in events.iter() {
        assert!(event.contains("read path cannot decrypt or mask"), "{event}");
        assert!(event.contains("users"), "{event}");
    }
}

/// A table protected only by a read-path mask never enters
/// [`WriteCatalog`]: a mask-only column has no transform, and that catalog
/// exists to say what a *write* must seal. Right for writes, and exactly
/// wrong for `COPY … TO`, whose rows leave as `CopyData` frames the read
/// path relays verbatim — the stored value *is* the plaintext, so the
/// statement hands the client the very value the mask exists to hide.
/// This is the sharpest form of the COPY leak: an encrypted column at
/// least leaves as ciphertext.
#[test]
fn a_mask_only_table_is_a_copy_out_site_in_both_forms_and_both_modes() {
    let out = ["COPY notes TO STDOUT", "COPY (SELECT body FROM notes) TO STDOUT"];

    let mut strict = rewriter(mask_only_catalog(OnUnprotected::Reject));
    for sql in out {
        let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
        assert!(refusal(&action).contains("notes"), "{sql}: {}", refusal(&action));
    }

    // The write direction is deliberately not a site. A mask-only column
    // is stored in plaintext, so a plaintext write to it is the correct
    // outcome — flagging one would be a false refusal, which is what keeps
    // operators off the fail-closed setting.
    for sql in [
        "COPY notes FROM STDIN",
        "COPY notes (body) FROM STDIN",
        "INSERT INTO notes (body) VALUES ('plaintext')",
        "UPDATE notes SET body = 'plaintext' WHERE body = 'x'",
    ] {
        assert!(
            matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
            "{sql}"
        );
    }

    // Under warn the reads relay with one warning each, naming the table,
    // and the write stays silent.
    let (_, events) = crate::captured_events(|| {
        let mut permissive = rewriter(mask_only_catalog(OnUnprotected::Warn));
        for sql in out.iter().chain(&["COPY notes FROM STDIN"]) {
            assert!(
                matches!(permissive.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
                "{sql}"
            );
        }
    });
    assert_eq!(events.len(), out.len(), "one warning per read, none for the write: {events:?}");
    for event in events.iter() {
        assert!(event.contains("notes"), "{event}");
    }
}

/// `SELECT lower(body) FROM notes` on a mask-only column is the sharpest
/// form of the computed-projection leak and used to be the one case
/// neither direction saw.
///
/// The write catalog has no entry for a mask-only column — a plaintext
/// write to one is correct — so resolving the projection against it raised
/// nothing. The read path's own backstop misses it too: PostgreSQL names
/// the field `lower`, not `body`, so a name-based match finds nothing to
/// act on, and the *stored* value is the plaintext. Under `reject` the
/// statement was relayed and the client got the value the mask exists to
/// hide, with no signal from either end.
///
/// A bare `SELECT body` must stay silent: it arrives with a real
/// `(table_oid, attnum)` and the read path masks it correctly, so
/// reporting it would refuse working SQL under `reject`.
#[test]
fn a_computed_mask_only_projection_is_a_write_path_site_in_both_modes() {
    let computed = [
        "SELECT lower(body) FROM notes",
        "SELECT body || '' FROM notes",
        "SELECT coalesce(body, '') AS body FROM notes",
        "SELECT lower(n.body) FROM notes n",
    ];

    let mut strict = rewriter(mask_only_catalog(OnUnprotected::Reject));
    for sql in computed {
        let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
        let message = refusal(&action);
        assert!(message.contains("body"), "{sql}: {message}");
        assert!(message.contains("cannot be decrypted or masked"), "{sql}: {message}");
    }

    // Selecting the column directly is what the read path handles, so it
    // is relayed untouched under the fail-closed policy.
    for sql in ["SELECT body FROM notes", "SELECT n.body FROM notes n", "SELECT * FROM notes"] {
        assert!(
            matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
            "{sql}"
        );
    }

    let (_, events) = crate::captured_events(|| {
        let mut permissive = rewriter(mask_only_catalog(OnUnprotected::Warn));
        for sql in computed.iter().chain(&["SELECT body FROM notes"]) {
            assert!(
                matches!(permissive.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
                "{sql}"
            );
        }
    });
    assert_eq!(
        events.len(),
        computed.len(),
        "one warning per computed projection, none for the direct select: {events:?}"
    );
    for event in events.iter() {
        assert!(event.contains("read path cannot decrypt or mask"), "{event}");
        assert!(event.contains("body"), "{event}");
    }
}

/// The same leak one level in: `SELECT lower(body) FROM (SELECT body FROM
/// notes) s`.
///
/// The base-table form above is caught by resolving the projection against
/// the catalog's read direction, but a derived table used to contribute no
/// columns to the enclosing scope at all — the scope walk took base tables
/// and parenthesised joins and nothing else — so `lower(body)` resolved
/// against nothing and the statement was relayed under `reject` too. The
/// read path's backstop is no help here either: PostgreSQL names the output
/// field `lower`.
///
/// A cast keeps the name and so *was* caught by the read path; it is
/// included to pin that the write path now sees it as well, rather than the
/// two directions disagreeing about the same statement.
#[test]
fn a_computed_projection_over_a_derived_table_is_a_site_in_both_modes() {
    let computed = [
        "SELECT lower(body) FROM (SELECT body FROM notes) s",
        "SELECT lower(s.body) FROM (SELECT body FROM notes) s",
        // Renamed on the way out: the enclosing query can only name it `b`.
        "SELECT lower(b) FROM (SELECT body AS b FROM notes) s",
        // Carried by a wildcard rather than named.
        "SELECT lower(body) FROM (SELECT * FROM notes) s",
        // Two levels of nesting.
        "SELECT lower(body) FROM (SELECT body FROM (SELECT body FROM notes) inner_s) s",
        "SELECT body::text || '' FROM (SELECT body FROM notes) s",
    ];

    let mut strict = rewriter(mask_only_catalog(OnUnprotected::Reject));
    for sql in computed {
        let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
        let message = refusal(&action);
        assert!(message.contains("cannot be decrypted or masked"), "{sql}: {message}");
    }

    // Projecting the column through unchanged is still the read path's
    // job, at any depth — reporting it would refuse working SQL.
    for sql in [
        "SELECT body FROM (SELECT body FROM notes) s",
        "SELECT s.body FROM (SELECT body FROM notes) s",
        "SELECT * FROM (SELECT body FROM notes) s",
        // A derived table over nothing protected stays out of scope.
        "SELECT lower(id) FROM (SELECT id FROM other) s",
    ] {
        assert!(
            matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
            "{sql}"
        );
    }

    let (_, events) = crate::captured_events(|| {
        let mut permissive = rewriter(mask_only_catalog(OnUnprotected::Warn));
        for sql in computed.iter().chain(&["SELECT body FROM (SELECT body FROM notes) s"]) {
            assert!(
                matches!(permissive.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
                "{sql}"
            );
        }
    });
    assert_eq!(
        events.len(),
        computed.len(),
        "one warning per computed projection, none for the direct select: {events:?}"
    );
    for event in events.iter() {
        assert!(event.contains("read path cannot decrypt or mask"), "{event}");
    }
}

/// A searchable predicate inside `COPY (query) TO STDOUT` is an ordinary
/// predicate: left alone it compares the client's plaintext against the
/// stored `blind_index || envelope`, matching no row — and "no rows" is
/// indistinguishable from "no such user". Under `reject` the leak site
/// refuses the statement before anything is rendered; under `warn` it
/// relays, so the predicate has to be rewritten for the relayed text to
/// mean what the client wrote.
#[test]
fn a_searchable_predicate_inside_a_copy_query_is_rewritten_or_reported() {
    use crate::rows::tests::INDEX_KEY;

    let sql = "COPY (SELECT id FROM users WHERE email = 'alice@example.com') TO STDOUT";

    let mut strict = rewriter(strict_catalog(true));
    let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
    assert!(refusal(&action).contains("protected table users"), "{}", refusal(&action));

    let _capture = crate::log_capture();
    let mut permissive = rewriter(catalog(true));
    let rewritten = rewritten_query(&mut permissive, sql).expect("rewritten");
    let expected = blind_index::compute(&INDEX_KEY, b"alice@example.com");
    assert!(!rewritten.contains("alice@example.com"), "{rewritten}");
    assert!(rewritten.contains("SUBSTRING(email FROM 1 FOR 32)"), "{rewritten}");
    assert!(rewritten.contains(&sealed_literal(&expected)), "{rewritten}");
    assert!(
        rewritten.starts_with("COPY (") && rewritten.ends_with(") TO STDOUT"),
        "still a COPY: {rewritten}"
    );

    // A predicate the blind index cannot answer, in a subquery the
    // leak-site walk does not reach, is raised as its own site instead of
    // being relayed to match nothing.
    let mut strict = rewriter(strict_catalog(true));
    let action = strict
        .on_frame(
            b'Q',
            &query_frame(
                "COPY (SELECT id FROM other WHERE id IN \
                 (SELECT id FROM users WHERE email LIKE 'a%')) TO STDOUT",
            ),
        )
        .unwrap();
    assert!(refusal(&action).contains("searchable column email"), "{}", refusal(&action));

    // `COPY ... FROM STDIN` is never re-rendered: only the `TO` direction
    // has a query source to rewrite, so nothing marks it changed and
    // `reassemble` keeps its source text byte for byte — including when a
    // statement beside it in the same batch *is* rewritten. Re-rendering
    // it would drop it back to text the wire has no form for.
    let mut permissive = rewriter(catalog(true));
    assert!(
        matches!(
            permissive.on_frame(b'Q', &query_frame("COPY users (email) FROM STDIN")).unwrap(),
            FrameAction::Relay
        ),
        "COPY FROM STDIN relayed verbatim"
    );
    let batch = rewritten_query(
        &mut permissive,
        "UPDATE users SET email = 'bob@x.io'; COPY users (email) FROM STDIN",
    )
    .expect("rewritten");
    assert!(batch.ends_with("COPY users (email) FROM STDIN"), "{batch}");
    assert!(!batch.contains("bob@x.io"), "{batch}");
}

/// A refusal inside a transaction reports the aborted state, so the
/// client rolls back rather than committing around the hole.
#[test]
fn refusal_reports_the_backend_transaction_state() {
    let status = Arc::new(AtomicU8::new(b'T'));
    let mut strict = QueryRewriter::new(
        strict_catalog(false),
        SessionPortals::new(),
        None,
        status.clone(),
        StartupSettings::default(),
    );
    let action = strict.on_frame(b'Q', &query_frame("COPY users FROM STDIN")).unwrap();
    let FrameAction::Reply(bytes) = action else { panic!("expected a refusal") };
    assert_eq!(bytes[bytes.len() - 1], b'E', "aborted transaction status");

    status.store(b'I', Ordering::Relaxed);
    let action = strict.on_frame(b'Q', &query_frame("COPY users FROM STDIN")).unwrap();
    let FrameAction::Reply(bytes) = action else { panic!("expected a refusal") };
    assert_eq!(bytes[bytes.len() - 1], b'I', "idle status");
}

/// Refusing a Parse puts the proxy in the backend's own error state: the
/// rest of the batch is discarded and Sync is answered with
/// ReadyForQuery.
#[test]
fn refused_parse_discards_the_batch_until_sync() {
    let mut strict = rewriter(strict_catalog(false));
    let parse = pgwire::encode_parse(b"s", b"COPY users FROM STDIN", &0i16.to_be_bytes());
    let action = strict.on_frame(b'P', &parse).unwrap();
    assert!(refusal(&action).contains("COPY"));

    // Bind and Execute are swallowed: the backend never saw the Parse.
    assert_eq!(strict.on_frame(b'B', b"").unwrap(), FrameAction::Reply(Vec::new()));
    assert_eq!(strict.on_frame(b'E', b"").unwrap(), FrameAction::Reply(Vec::new()));
    let FrameAction::Reply(sync) = strict.on_frame(b'S', b"").unwrap() else {
        panic!("Sync must be answered")
    };
    assert_eq!(sync[0], b'Z');
    // ... and the session carries on.
    assert!(matches!(strict.on_frame(b'Q', &query_frame("SELECT 1")).unwrap(), FrameAction::Relay));
}

// --- upsert and MERGE ------------------------------------------------

// --- search_path -----------------------------------------------------

// --- standard_conforming_strings ---------------------------------------

// --- identifier folding ------------------------------------------------

// --- SQL text fidelity -----------------------------------------------

/// Only the statement that changed is re-rendered; the rest of the batch
/// reaches the server byte-for-byte as the client wrote it.
#[test]
fn untouched_statements_keep_their_original_text() {
    let mut rewriter = rewriter(catalog(false));
    let original = "/* keep me */ SELECT 1 -- and me\n; INSERT INTO users (email) \
                    VALUES ('a@b.io') ;  SELECT   'x'  ,  $tag$ raw ; body $tag$ ;";
    let sql = rewritten_query(&mut rewriter, original).expect("rewritten");
    assert!(sql.starts_with("/* keep me */ SELECT 1 -- and me\n; "), "{sql}");
    assert!(sql.ends_with(";  SELECT   'x'  ,  $tag$ raw ; body $tag$ ;"), "{sql}");
    assert!(!sql.contains("a@b.io"), "{sql}");
    assert_eq!(open_hex_literal(&sql, false), b"a@b.io");
}

/// The regression the mis-lexing produced: a batch mixing a rewritten
/// INSERT with a digit-tagged statement lost the untouched statement's
/// source text, comments included, because `reassemble` fell back to
/// re-rendering everything.
#[test]
fn a_digit_tagged_statement_keeps_its_source_text() {
    let mut rewriter = rewriter(catalog(false));
    let original =
        "INSERT INTO users (email) VALUES ('a@b.io'); SELECT $tag1$hello$tag1$ /* keep me */";
    let sql = rewritten_query(&mut rewriter, original).expect("rewritten");
    assert!(sql.contains("$tag1$hello$tag1$ /* keep me */"), "{sql}");
    assert!(!sql.contains("a@b.io"), "{sql}");
    assert_eq!(open_hex_literal(&sql, false), b"a@b.io");
}

// --- searchable predicates -------------------------------------------

#[test]
fn in_list_and_any_array_rewrite_to_index_matches() {
    use crate::rows::tests::INDEX_KEY;

    let mut rewriter = rewriter(catalog(true));
    let expected = blind_index::compute(&INDEX_KEY, b"a@b.io");
    for sql in [
        "SELECT id FROM users WHERE email IN ('a@b.io', 'c@d.io')",
        "SELECT id FROM users WHERE email = ANY(ARRAY['a@b.io', 'c@d.io'])",
    ] {
        let rewritten = rewritten_query(&mut rewriter, sql).expect("rewritten");
        assert!(!rewritten.contains("a@b.io"), "{rewritten}");
        assert!(rewritten.contains("SUBSTRING(email FROM 1 FOR 32)"), "{rewritten}");
        assert!(rewritten.contains(&hex::encode(expected)), "{rewritten}");
    }

    // Bound placeholders in the list are indexed at Bind time.
    let parse = pgwire::encode_parse(
        b"in",
        b"SELECT id FROM users WHERE email IN ($1, $2)",
        &0i16.to_be_bytes(),
    );
    let FrameAction::Replace(rewritten) = rewriter.on_frame(b'P', &parse).unwrap() else {
        panic!("parse not rewritten")
    };
    let reparsed = pgwire::parse_parse(&rewritten).unwrap();
    assert!(std::str::from_utf8(reparsed.query)
        .unwrap()
        .contains("SUBSTRING(email FROM 1 FOR 32) IN ($1, $2)"));
    let bind = pgwire::encode_bind(
        b"",
        b"in",
        &[],
        &[Some(Cow::Borrowed(b"a@b.io".as_slice())), Some(Cow::Borrowed(b"c@d.io".as_slice()))],
        &0i16.to_be_bytes(),
    )
    .unwrap();
    let FrameAction::Replace(rewritten) = rewriter.on_frame(b'B', &bind).unwrap() else {
        panic!("bind not rewritten")
    };
    let bound = pgwire::parse_bind(&rewritten).unwrap();
    assert_eq!(bound.params[0].unwrap(), format!("\\x{}", hex::encode(expected)).as_bytes());
}

/// `= ANY($1)` is the shape sqlx and asyncpg give a multi-value lookup:
/// one bound array, not a list of placeholders. The SQL is the same
/// index-prefix match `ARRAY[...]` produces; the array itself is decoded,
/// indexed and re-encoded as `bytea[]` at Bind time.
#[test]
fn a_bound_any_array_is_indexed_element_by_element_at_bind_time() {
    use crate::rows::tests::INDEX_KEY;

    let indexed = |value: &[u8]| blind_index::compute(&INDEX_KEY, value);
    let mut rewriter = rewriter(catalog(true));
    let sql = rewritten_parse(&mut rewriter, b"any", "SELECT id FROM users WHERE email = ANY($1)")
        .expect("rewritten");
    assert!(sql.contains("SUBSTRING(email FROM 1 FOR 32) = ANY($1)"), "{sql}");

    // Binary format: bytea[] in, bytea[] out, NULL elements preserved.
    let array = binary_array(17, &[Some(b"a@b.io"), None, Some(b"c@d.io")]);
    let FrameAction::Replace(rewritten) =
        rewriter.on_frame(b'B', &bind_frame(b"any", &[1], &[Some(&array)])).unwrap()
    else {
        panic!("bind not rewritten")
    };
    let bound = pgwire::parse_bind(&rewritten).unwrap();
    assert_eq!(
        bound.params[0].unwrap(),
        binary_array(17, &[Some(&indexed(b"a@b.io")), None, Some(&indexed(b"c@d.io"))]),
    );

    // Text format: an array literal of `\x` hex, with the backslash
    // escaped the way a quoted array element needs it.
    let FrameAction::Replace(rewritten) = rewriter
        .on_frame(b'B', &bind_frame(b"any", &[0], &[Some(b"{a@b.io,NULL,\"c@d.io\"}")]))
        .unwrap()
    else {
        panic!("bind not rewritten")
    };
    let bound = pgwire::parse_bind(&rewritten).unwrap();
    assert_eq!(
        bound.params[0].unwrap(),
        format!(
            "{{\"\\\\x{}\",NULL,\"\\\\x{}\"}}",
            hex::encode(indexed(b"a@b.io")),
            hex::encode(indexed(b"c@d.io"))
        )
        .as_bytes(),
    );
}

/// An array the codec cannot index faithfully must not go on the wire
/// half-indexed: that is a *valid* query returning the wrong rows. It
/// falls back to the same signal the SQL rewrite raises, one message
/// later.
#[test]
fn an_undecodable_any_array_falls_back_to_the_predicate_signal() {
    // An int4 element type: not a value this proxy ever sealed.
    let ints = binary_array(23, &[Some(&1i32.to_be_bytes())]);
    // Truncated, and a nested array literal.
    let truncated = binary_array(17, &[Some(b"a@b.io")]);
    let truncated = truncated[..truncated.len() - 2].to_vec();
    for (format, param) in [
        (1i16, ints),
        (1, truncated),
        (0, b"{{a@b.io},{c@d.io}}".to_vec()),
        (0, b"[1:2]={a@b.io,c@d.io}".to_vec()),
    ] {
        let mut permissive = rewriter(catalog(true));
        rewritten_parse(&mut permissive, b"any", "SELECT id FROM users WHERE email = ANY($1)")
            .expect("rewritten");
        let bind = bind_frame(b"any", &[format], &[Some(&param)]);
        let relayed = match permissive.on_frame(b'B', &bind).unwrap() {
            FrameAction::Relay => param.clone(),
            FrameAction::Replace(body) => {
                pgwire::parse_bind(&body).unwrap().params[0].unwrap().to_vec()
            }
            FrameAction::Reply(_) | FrameAction::RefuseAndClose(_) => {
                panic!("warn must not refuse: {param:?}")
            }
        };
        assert_eq!(relayed, param, "warn relays the array untouched");

        let mut strict = rewriter(strict_catalog(true));
        rewritten_parse(&mut strict, b"any", "SELECT id FROM users WHERE email = ANY($1)")
            .expect("rewritten");
        let action = strict.on_frame(b'B', &bind).unwrap();
        assert!(refusal(&action).contains("searchable column email"), "{param:?}");
        // The refusal owns the batch until Sync, exactly like a refused
        // Parse: the backend never saw the Bind.
        assert_eq!(strict.on_frame(b'E', b"\0\0\0\0\0").unwrap(), FrameAction::Reply(Vec::new()));
        let FrameAction::Reply(ready) = strict.on_frame(b'S', b"").unwrap() else {
            panic!("Sync answers with ReadyForQuery")
        };
        assert_eq!(ready[0], b'Z');
    }
}

/// The other parameters of a Bind are still transformed when one array
/// cannot be indexed — a sealed parameter relayed as plaintext because
/// some *other* parameter was undecodable would write the plaintext this
/// proxy exists to keep out of the database.
#[test]
fn a_fallback_array_does_not_drop_the_other_parameters_of_its_bind() {
    let mut rewriter = rewriter(catalog(true));
    let sql = rewritten_parse(
        &mut rewriter,
        b"mixed",
        "UPDATE users SET email = $1 WHERE email = ANY($2)",
    );
    assert!(sql.is_some());
    let ints = binary_array(23, &[Some(&1i32.to_be_bytes())]);
    let bind = bind_frame(b"mixed", &[1], &[Some(b"new@b.io"), Some(&ints)]);
    let FrameAction::Replace(rewritten) = rewriter.on_frame(b'B', &bind).unwrap() else {
        panic!("the sealed parameter must still be sealed")
    };
    let bound = pgwire::parse_bind(&rewritten).unwrap();
    assert_ne!(bound.params[0].unwrap(), b"new@b.io");
    assert_eq!(bound.params[1].unwrap(), ints, "the array is relayed as it came");
}

/// One Bind can carry more than one array that cannot be indexed, and the
/// operator has to be told about all of them: naming only the last one
/// sends them to fix one site and meet the other on the next run.
#[test]
fn every_un_indexable_array_of_a_bind_is_named_not_only_the_last() {
    let catalog = Arc::new(WriteCatalog::new(
        &[column("email", transform(true), true), column("phone", transform(true), true)],
        OnUnprotected::Reject,
    ));
    let mut strict = rewriter(catalog);
    rewritten_parse(
        &mut strict,
        b"two",
        "SELECT id FROM users WHERE email = ANY($1) OR phone = ANY($2)",
    )
    .expect("rewritten");
    // int4 elements: nothing this proxy ever sealed, so both fall back.
    let ints = binary_array(23, &[Some(&1i32.to_be_bytes())]);
    let bind = bind_frame(b"two", &[1, 1], &[Some(&ints), Some(&ints)]);
    let FrameAction::Reply(frames) = strict.on_frame(b'B', &bind).unwrap() else {
        panic!("strict mode must refuse a Bind it cannot index")
    };
    let message = String::from_utf8_lossy(&frames);
    assert!(message.contains("email") && message.contains("phone"), "{message}");
}

// --- logging ---------------------------------------------------------

/// Every passthrough site, driven with a distinct plaintext, and then the
/// whole log grepped for those plaintexts. Each of these values is bound
/// to a protected column or embedded in SQL the parser choked on, so any
/// of them appearing in an event is the disclosure this module's logging
/// rules exist to prevent.
#[test]
fn no_event_from_the_write_path_carries_a_plaintext_value() {
    let drive =
        || {
            // The ambiguity site needs two protected relations in scope, so it
            // is driven through a catalog of its own.
            let mut ambiguous = rewriter(ambiguous_catalog(OnUnprotected::Warn));
            // The remaining sites each need a session the loop below cannot
            // be: one whose column is not searchable, one that still resolves
            // unqualified names after turning standard_conforming_strings off
            // (the loop's rewriter has since seen `SET search_path`), and one
            // with a read context declaring a row key. Built here, before the
            // binding below shadows the helper that makes them.
            let mut unindexed = rewriter(catalog(false));
            let mut escapes = rewriter(catalog(true));
            let mut row_bound = row_bound_rewriter();
            let mut rewriter = rewriter(catalog(true));
            for sql in [
                "INSERT INTO users (email) VALUES (lower('alice@secret.test'))",
                "UPDATE users SET email = concat('bob', '@secret.test')",
                "INSERT INTO users VALUES (1, 'carol@secret.test')",
                "INSERT INTO users (email) SELECT email FROM other",
                "COPY users (email) FROM STDIN",
                "COPY users TO STDOUT",
                "COPY (SELECT email FROM users WHERE email LIKE 'sara@secret.test%') TO STDOUT",
                "SELECT upper(email) FROM users",
                "MERGE INTO users u USING staging s ON u.id = s.id \
             WHEN MATCHED THEN UPDATE SET email = s.email",
                "PREPARE ins AS INSERT INTO users (email) VALUES ('dave@secret.test')",
                "SELECT id FROM users WHERE email LIKE 'erin@secret.test%'",
                "SELECT id FROM users WHERE email IN ('fred@secret.test', lower('x'))",
                "UPDATE users SET email 'gina@secret.test'",
                "SET search_path TO tenant7",
                "SET SCHEMA 'tenant7'",
                "SELECT set_config('search_path', 'tenant7', false)",
                "SET standard_conforming_strings = off",
                "INSERT INTO users (email) VALUES ('hank@secret.test')",
                // The non-`'...'` literal syntaxes. These now seal rather than
                // pass through, but they must not reach the log on the way —
                // and wrapping one in a function call puts it back on a
                // passthrough site, where the value is logged if anything is.
                r"INSERT INTO users (email) VALUES (lower(E'ivan\'s@secret.test'))",
                "INSERT INTO users (email) VALUES (lower($$judy@secret.test$$))",
                r"UPDATE users SET email = E'kate\'s@secret.test'",
                r"SELECT id FROM users WHERE email LIKE E'liam\'s@secret.test%'",
            ] {
                // Errors are the point of some of these; only the log matters.
                drop(rewriter.on_frame(b'Q', &query_frame(sql)));
            }
            // A Query body that is not UTF-8 at all, which no `&str` can be.
            drop(rewriter.on_frame(b'Q', &[b'S', b'E', 0xff, 0xfe, 0]));
            drop(ambiguous.on_frame(
                b'Q',
                &query_frame(
                    "SELECT * FROM users u JOIN accounts a ON u.id = a.uid \
                 WHERE email = 'mona@secret.test'",
                ),
            ));
            drop(unindexed.on_frame(
                b'Q',
                &query_frame("SELECT id FROM users WHERE email = 'opal@secret.test'"),
            ));
            for sql in [
                "SET standard_conforming_strings = off",
                r"INSERT INTO users (email) VALUES ('nina\secret.test')",
            ] {
                drop(escapes.on_frame(b'Q', &query_frame(sql)));
            }
            for sql in [
                "INSERT INTO users (email) VALUES ('quinn@secret.test')",
                "UPDATE users SET email = 'rita@secret.test'",
                "UPDATE users SET email = 'tess@secret.test', id = 99 WHERE id = 7",
            ] {
                drop(row_bound.on_frame(b'Q', &query_frame(sql)));
            }
        };

    // [`crate::captured_events`] drives this twice and throws the first
    // pass away — see there for why a capture test that skips that step
    // can silently stop capturing.
    let (_, lines) = crate::captured_events(drive);
    let events = lines.join("\n");
    assert!(events.contains("passing through unencrypted"), "the sites did emit: {events}");
    for plaintext in [
        "alice", "bob", "carol", "dave", "erin", "fred", "gina", "hank", "ivan", "judy", "kate",
        "liam", "mona", "nina", "opal", "quinn", "rita", "sara", "tess", "secret",
    ] {
        assert!(!events.contains(plaintext), "{plaintext} reached the log:\n{events}");
    }

    // Every site is driven, and stays driven. The match is exhaustive, so
    // a variant added to [`Unprotected`] without a driver above stops this
    // test compiling; the assertion then fails until something actually
    // emits it. The needles identify a site in the log by its warning
    // wording, plus the field that tells the two COPY directions apart.
    let table = ObjectName(vec![Ident::new("users")]);
    let unparseable = parse_sql("UPDATE users SET email 'zoe'").expect_err("does not parse");
    for site in [
        Unprotected::NonUtf8,
        Unprotected::Unparseable(&unparseable),
        Unprotected::NoColumnList(&table),
        Unprotected::InsertFromSelect(&table),
        Unprotected::Copy { table: &table, to: false },
        Unprotected::Copy { table: &table, to: true },
        Unprotected::CopyQuery { table: "public.users".to_owned() },
        Unprotected::Unsupported { table: &table, shape: "MERGE" },
        Unprotected::AmbiguousLiteral { column: "email" },
        Unprotected::UnsupportedValue { column: "email", shape: "function call" },
        Unprotected::ComputedColumn { column: "email".to_owned(), shape: "function call" },
        Unprotected::RowKeyMissing {
            table: "public.users".to_owned(),
            column: "id".to_owned(),
            shape: "INSERT without the row key in its column list",
        },
        Unprotected::RowKeyReassigned { table: "public.users".to_owned(), column: "id".to_owned() },
        Unprotected::Predicate { column: "email".to_owned(), shape: "LIKE" },
        Unprotected::AmbiguousColumn { column: "email".to_owned(), shape: "comparison" },
        Unprotected::UnindexedPredicate { column: "email".to_owned(), shape: "comparison" },
        Unprotected::SearchPathChanged,
        Unprotected::EscapeStringsChanged,
        Unprotected::SearchPath(&table),
    ] {
        let needles: &[&str] = match &site {
            Unprotected::NonUtf8 => &["query is not valid UTF-8"],
            Unprotected::Unparseable(_) => &["unparseable SQL"],
            Unprotected::NoColumnList(_) => &["INSERT without a column list"],
            Unprotected::InsertFromSelect(_) => &["INSERT ... SELECT into a protected table"],
            Unprotected::Copy { to: false, .. } => {
                &["COPY on a protected table", r#"direction="from""#]
            }
            Unprotected::Copy { to: true, .. } => {
                &["COPY on a protected table", r#"direction="to""#]
            }
            Unprotected::CopyQuery { .. } => &["COPY of a query over a protected table"],
            Unprotected::Unsupported { .. } => {
                &["statement writes a protected table but is not rewritten"]
            }
            Unprotected::AmbiguousLiteral { .. } => &["string literal contains a backslash"],
            Unprotected::UnsupportedValue { .. } => {
                &["unsupported expression for a protected column"]
            }
            Unprotected::ComputedColumn { .. } => {
                &["protected column projected through an expression"]
            }
            Unprotected::RowKeyMissing { .. } => &["row-bound table written without its row key"],
            Unprotected::RowKeyReassigned { .. } => {
                &["assignment list on a row-bound table writes its row key"]
            }
            Unprotected::Predicate { .. } => &["unsupported predicate for a searchable column"],
            Unprotected::AmbiguousColumn { .. } => {
                &["unqualified column matches a protected column in more than one relation"]
            }
            Unprotected::UnindexedPredicate { .. } => {
                &["predicate over a protected column with no equality index"]
            }
            Unprotected::SearchPathChanged => &["session changed search_path"],
            Unprotected::EscapeStringsChanged => {
                &["session turned standard_conforming_strings off"]
            }
            Unprotected::SearchPath(_) => &["unqualified name may be a protected table"],
        };
        assert!(
            lines.iter().any(|line| needles.iter().all(|needle| line.contains(needle))),
            "no event drove the site logging {needles:?}:\n{events}"
        );
    }
}
/// A row-key column whose name is not already all-lowercase ASCII must
/// still be recognised when a statement names it the way PostgreSQL folds
/// it.
///
/// The row-key sites used to compare a folded SQL identifier against
/// `spec.name.to_lowercase()`, and Rust's `to_lowercase` is full Unicode
/// folding where the server's is ASCII-only. `Ämail` became `ämail` on one
/// side and stayed `Ämail` on the other, and a quoted `"rowKey"` — the
/// reference config validation tells the operator is the only one that will
/// match a mixed-case configured name — folded to `rowKey` against a
/// `rowkey` that nothing produces. Either way the row key resolved to
/// nothing: `RowKeyMissing`, which refuses valid SQL under `reject` and
/// under `warn` seals cell-only, quietly weaker than the configuration
/// promises. `crates/proxy/src/encrypt/catalog.rs` pins the same rule for
/// protected column names.
#[test]
fn a_row_key_named_outside_lowercase_ascii_is_still_recognised() {
    // (configured row_key, how a statement names it)
    for (configured, reference) in [
        ("id", "id"),
        // Non-ASCII: the server folds the ASCII half and leaves `Ä` alone.
        ("Ämail", "Ämail"),
        ("Ämail", "ÄMAIL"),
        // Mixed case reachable only through a quoted reference.
        ("rowKey", "\"rowKey\""),
    ] {
        let mut rewriter = row_bound_rewriter_named(configured);
        let sql = format!("UPDATE users SET email = 'alice@secret.test' WHERE {reference} = 7");
        let rewritten = rewritten_query(&mut rewriter, &sql).expect("rewritten");
        let stored = hex::decode(sealed_hex(&rewritten).expect("a sealed literal")).unwrap();
        let (_, envelope) = blind_index::split(&stored).expect("searchable column");
        assert!(
            envelope.starts_with(dbsec_core::envelope::MAGIC_V3),
            "{configured} named as {reference} must seal row-bound, not cell-only"
        );
    }

    // The other direction, so the comparison is not simply case-blind: an
    // unquoted reference cannot name a row key that only a quoted one can.
    let mut rewriter = row_bound_rewriter_named("rowKey");
    let rewritten = rewritten_query(
        &mut rewriter,
        "UPDATE users SET email = 'alice@secret.test' WHERE rowKey = 7",
    )
    .expect("rewritten");
    let stored = hex::decode(sealed_hex(&rewritten).expect("a sealed literal")).unwrap();
    let (_, envelope) = blind_index::split(&stored).expect("searchable column");
    assert!(
        envelope.starts_with(dbsec_core::envelope::MAGIC),
        "an unquoted rowKey folds to rowkey, which names no configured row key"
    );
}
