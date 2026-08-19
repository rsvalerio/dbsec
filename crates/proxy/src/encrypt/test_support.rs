//! Fixtures shared by every test under `encrypt`.
//!
//! Split out of the test module that lived in `mod.rs`: the helpers and the
//! end-to-end suite that used them were two different things sharing one file,
//! and together they made it the largest file in the module tree. Catalogs,
//! rewriters, frame builders and the sealed-literal readers live here; the
//! suite lives in [`super::tests_e2e`], and each layer's own unit tests sit in
//! that layer.

use std::borrow::Cow;

use super::*;
use crate::columns::ProtectedColumn;
use crate::rowkey;
use crate::rows::tests::transform;
use crate::session::FrameAction;
use dbsec_core::pgwire;

pub(in crate::encrypt) fn column(
    name: &str,
    transform: Arc<dyn FieldTransform>,
    searchable: bool,
) -> ProtectedColumn {
    ProtectedColumn {
        schema: "public".into(),
        table: "users".into(),
        column: name.into(),
        transform: Some(transform),
        searchable,
        readable: true,
        mask: None,
    }
}

pub(in crate::encrypt) fn catalog(searchable: bool) -> Arc<WriteCatalog> {
    Arc::new(WriteCatalog::new(
        &[column("email", transform(searchable), searchable)],
        OnUnprotected::Warn,
    ))
}

/// The two other transform kinds, which are never searchable: their
/// stored form is deterministic but it is not the plaintext, so a
/// predicate over one matches nothing just as an unsearchable `encrypt`
/// column does.
pub(in crate::encrypt) fn fpe_transform() -> Arc<dyn FieldTransform> {
    Arc::new(dbsec_core::transform::FpeTransform::new(
        Arc::new(crate::rows::tests::OneKey),
        "public.users.email".to_owned(),
        true,
    ))
}

pub(in crate::encrypt) fn token_transform() -> Arc<dyn FieldTransform> {
    Arc::new(dbsec_core::transform::TokenTransform::new(
        Arc::new(crate::rows::tests::OneKey),
        "public.users.email".to_owned(),
    ))
}

/// A catalog holding one column with an arbitrary transform, so the
/// predicate tests can cover every kind under both policies.
pub(in crate::encrypt) fn catalog_of(
    transform: Arc<dyn FieldTransform>,
    searchable: bool,
    on_unprotected: OnUnprotected,
) -> Arc<WriteCatalog> {
    Arc::new(WriteCatalog::new(&[column("email", transform, searchable)], on_unprotected))
}

/// Two protected tables that both carry a searchable `email`, so an
/// unqualified `email` in a query joining them resolves to neither.
pub(in crate::encrypt) fn ambiguous_catalog(on_unprotected: OnUnprotected) -> Arc<WriteCatalog> {
    let mut accounts = column("email", transform(true), true);
    accounts.table = "accounts".into();
    let users = column("email", transform(true), true);
    Arc::new(WriteCatalog::new(&[users, accounts], on_unprotected))
}

/// A table whose only protection is a read-path mask. Its column has no
/// transform, so nothing on the write path seals it and its stored form is
/// the plaintext — the mask applied on the way out is all that hides it.
pub(in crate::encrypt) fn mask_only_catalog(on_unprotected: OnUnprotected) -> Arc<WriteCatalog> {
    Arc::new(WriteCatalog::new(
        &[ProtectedColumn {
            schema: "public".into(),
            table: "notes".into(),
            column: "body".into(),
            transform: None,
            searchable: false,
            readable: false,
            mask: Some(dbsec_core::mask::MaskSpec { keep_first: 1, keep_last: 0, mask_with: '*' }),
        }],
        on_unprotected,
    ))
}

pub(in crate::encrypt) fn strict_catalog(searchable: bool) -> Arc<WriteCatalog> {
    Arc::new(WriteCatalog::new(
        &[column("email", transform(searchable), searchable)],
        OnUnprotected::Reject,
    ))
}

/// A rewriter with extended-protocol state of its own; tests that also
/// drive the read path build the [`SessionPortals`] themselves and share
/// it (see `rows::tests::session`).
pub(in crate::encrypt) fn rewriter(catalog: Arc<WriteCatalog>) -> QueryRewriter {
    QueryRewriter::new(
        catalog,
        SessionPortals::new(),
        None,
        Arc::new(AtomicU8::new(b'I')),
        StartupSettings::default(),
    )
}

/// A rewriter whose `users` table declares `id` as its row key.
///
/// [`rewriter`] passes no read context, and `row_key_spec` reads the
/// declarations out of that context — so without one every table is
/// cell-bound and the row-key sites cannot fire at all.
pub(in crate::encrypt) fn row_bound_rewriter() -> QueryRewriter {
    use crate::rows::{Resolved, ResolvedRowKey, RowContext, DEFAULT_MAX_PROTECTED_VALUE_LEN};

    let spec = ResolvedRowKey {
        attnum: 1,
        type_oid: rowkey::oid::INT4,
        name: "id".into(),
        table: "public.users".into(),
    };
    let rows = Arc::new(RowContext::new(
        Resolved {
            row_key_by_table: std::collections::HashMap::from([(
                ("public".to_owned(), "users".to_owned()),
                spec,
            )]),
            ..Default::default()
        },
        OnUnprotected::Warn,
        DEFAULT_MAX_PROTECTED_VALUE_LEN,
    ));
    QueryRewriter::new(
        catalog(true),
        SessionPortals::new(),
        Some(rows),
        Arc::new(AtomicU8::new(b'I')),
        StartupSettings::default(),
    )
}

pub(in crate::encrypt) fn query_frame(sql: &str) -> Vec<u8> {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    body
}

/// The SQL a Query frame was rewritten into, or `None` when it was
/// relayed untouched.
pub(in crate::encrypt) fn rewritten_query(
    rewriter: &mut QueryRewriter,
    sql: &str,
) -> Option<String> {
    match rewriter.on_frame(b'Q', &query_frame(sql)).unwrap() {
        FrameAction::Relay => None,
        FrameAction::Replace(body) => {
            Some(String::from_utf8(body[..body.len() - 1].to_vec()).unwrap())
        }
        FrameAction::Reply(_) | FrameAction::RefuseAndClose(_) => {
            panic!("refused: {sql}")
        }
    }
}

/// The ErrorResponse text of a refused frame.
pub(in crate::encrypt) fn refusal(action: &FrameAction) -> String {
    let FrameAction::Reply(bytes) = action else { panic!("expected a refusal") };
    assert_eq!(bytes[0], b'E', "first frame is an ErrorResponse");
    String::from_utf8_lossy(bytes).into_owned()
}

/// How a sealed BYTEA value appears in rewritten SQL: the escape-string
/// literal [`bytea_literal`] emits, with its backslash doubled.
pub(in crate::encrypt) const SEALED_PREFIX: &str = r"E'\\x";

pub(in crate::encrypt) fn sealed_literal(value: &[u8]) -> String {
    format!("{SEALED_PREFIX}{}'", hex::encode(value))
}

/// Extracts the sealed hex literal out of a rewritten statement and
/// opens it.
pub(in crate::encrypt) fn open_hex_literal(sql: &str, searchable: bool) -> Vec<u8> {
    let stored = hex::decode(sealed_hex(sql).expect("hex literal")).unwrap();
    transform(searchable).open(&stored, None).unwrap().expect("opens")
}

/// The hex digits of the first sealed literal in a rewritten statement.
pub(in crate::encrypt) fn sealed_hex(sql: &str) -> Option<&str> {
    let start = sql.find(SEALED_PREFIX)? + SEALED_PREFIX.len();
    let end = sql[start..].find('\'')? + start;
    Some(&sql[start..end])
}

/// Two protected columns of one table under *different* transforms, so a
/// placeholder feeding both cannot be satisfied by one value on the wire.
pub(in crate::encrypt) fn two_column_catalog(on_unprotected: OnUnprotected) -> Arc<WriteCatalog> {
    Arc::new(WriteCatalog::new(
        &[
            column("email", transform(false), false),
            column("backup_email", transform(false), false),
        ],
        on_unprotected,
    ))
}

/// Parses a statement and returns the rewritten SQL text.
pub(in crate::encrypt) fn rewritten_parse(
    rewriter: &mut QueryRewriter,
    statement: &[u8],
    sql: &str,
) -> Option<String> {
    let parse = pgwire::encode_parse(statement, sql.as_bytes(), &0i16.to_be_bytes());
    match rewriter.on_frame(b'P', &parse).unwrap() {
        FrameAction::Relay => None,
        FrameAction::Replace(body) => {
            Some(String::from_utf8(pgwire::parse_parse(&body).unwrap().query.to_vec()).unwrap())
        }
        FrameAction::Reply(_) | FrameAction::RefuseAndClose(_) => {
            panic!("refused: {sql}")
        }
    }
}

pub(in crate::encrypt) fn bind_frame(
    statement: &[u8],
    formats: &[i16],
    params: &[Option<&[u8]>],
) -> Vec<u8> {
    let params: Vec<_> = params.iter().map(|p| p.map(Cow::Borrowed)).collect();
    pgwire::encode_bind(b"", statement, formats, &params, &0i16.to_be_bytes()).unwrap()
}
