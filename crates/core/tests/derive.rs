//! `#[derive(Protect)]` against a `Protector`: the generated seal/open/term/
//! mask agree with calling the protector by hand, and the struct's own policy
//! is the one the protector was built from.
#![cfg(all(feature = "derive", feature = "keyfile"))]

use std::sync::Arc;

use dbsec_core::envelope::{KeyId, RowKey};
use dbsec_core::keys::{Key, KeySource};
use dbsec_core::policy::{Policy, TransformKind};
use dbsec_core::protector::Protector;
use dbsec_core::{Error, Protect};

struct OneKey;
const KEY_ID: KeyId = [5u8; 16];

impl KeySource for OneKey {
    fn active_key(&self) -> Result<(KeyId, Key), Error> {
        Ok((KEY_ID, Key::new([2u8; 32])))
    }
    fn key(&self, id: &KeyId) -> Result<Key, Error> {
        (id == &KEY_ID).then(|| Key::new([2u8; 32])).ok_or(Error::Decrypt)
    }
    fn index_key(&self, _name: &str) -> Result<Key, Error> {
        Ok(Key::new([3u8; 32]))
    }
}

#[derive(Protect, Clone, Debug, PartialEq)]
#[dbsec(table = "users", row_key = "id", sealed_derive(Debug, Clone))]
struct User {
    id: i64,
    #[dbsec(searchable)]
    email: String,
    #[dbsec]
    ssn: Option<String>,
    #[dbsec(fpe, mask(keep_last = 4))]
    phone: String,
    #[dbsec(token, column = "national_id")]
    nid: String,
    #[dbsec(none, mask(keep_first = 2))]
    note: String,
    #[dbsec]
    blob: Vec<u8>,
    plain: String,
}

/// No row key: a table whose values are cell-bound only.
#[derive(Protect, Clone, Debug, PartialEq)]
#[dbsec(table = "audit.events")]
struct Event {
    seq: i32,
    #[dbsec]
    payload: Vec<u8>,
}

fn protector() -> Protector {
    let mut policy = User::policy();
    let events = Event::policy();
    policy.columns.extend(events.columns);
    policy.tables.extend(events.tables);
    Protector::new(policy, Arc::new(OneKey)).unwrap()
}

fn user() -> User {
    User {
        id: 42,
        email: "a@b.io".into(),
        ssn: Some("078-05-1120".into()),
        phone: "555-123-4567".into(),
        nid: "X123456".into(),
        note: "hello world".into(),
        blob: vec![1, 2, 3],
        plain: "left alone".into(),
    }
}

#[test]
fn the_struct_declares_the_policy() {
    let policy = User::policy();
    assert_eq!(User::TABLE, "public.users");
    let names: Vec<String> = policy.columns.iter().map(|c| c.qualified_name()).collect();
    assert_eq!(
        names,
        [
            "public.users.email",
            "public.users.ssn",
            "public.users.phone",
            "public.users.national_id",
            "public.users.note",
            "public.users.blob"
        ]
    );
    assert!(policy.columns[0].searchable);
    assert_eq!(policy.columns[2].transform, TransformKind::Fpe);
    assert_eq!(policy.columns[2].mask.unwrap().keep_last, 4);
    assert_eq!(policy.columns[3].transform, TransformKind::Token);
    assert_eq!(policy.columns[4].transform, TransformKind::None);
    assert_eq!(policy.tables.len(), 1);
    assert_eq!(policy.tables[0].row_key, "id");
    policy.validate().unwrap();

    let events = Event::policy();
    assert_eq!(Event::TABLE, "audit.events");
    assert!(events.tables.is_empty());
}

#[test]
fn seal_then_open_round_trips_and_binds_the_row() {
    let p = protector();
    let original = user();
    let sealed = original.seal(&p).unwrap();

    // Stored forms: a searchable row-bound envelope, shape-preserving FPE, a
    // token, plaintext for the mask-only column, and plain fields untouched.
    assert_eq!(&sealed.email[32..36], b"DBS3");
    assert_ne!(sealed.phone, "555-123-4567");
    assert_eq!(sealed.phone.len(), "555-123-4567".len());
    assert_ne!(sealed.nid, "X123456");
    assert_eq!(sealed.note, "hello world");
    assert_eq!(sealed.plain, "left alone");
    assert_eq!(sealed.id, 42);

    // By hand, the same bytes: the derive adds no second convention.
    let row = RowKey::from_i64(42);
    assert_eq!(p.seal("users.national_id", b"X123456", Some(&row)).unwrap(), sealed.nid.as_bytes());
    assert_eq!(
        p.seal("users.phone", b"555-123-4567", Some(&row)).unwrap(),
        sealed.phone.as_bytes()
    );

    // Opening refuses the token column: it is irreversible, and the struct
    // asked for a `String` back. So `open` on the whole record is an error
    // until the token field is read separately — which is what the policy
    // says about tokens, surfaced rather than hidden.
    assert!(matches!(sealed.clone().open(&p), Err(Error::NotReadable(_))));
}

#[derive(Protect, Clone, Debug, PartialEq)]
#[dbsec(table = "users", row_key = "id", sealed_derive(Debug, Clone))]
struct Readable {
    id: i64,
    #[dbsec(searchable)]
    email: String,
    #[dbsec]
    ssn: Option<String>,
    #[dbsec(fpe, mask(keep_last = 4))]
    phone: String,
    #[dbsec(none, mask(keep_first = 2))]
    note: String,
    #[dbsec]
    blob: Vec<u8>,
    plain: String,
}

fn readable() -> Readable {
    Readable {
        id: 42,
        email: "a@b.io".into(),
        ssn: Some("078-05-1120".into()),
        phone: "555-123-4567".into(),
        note: "hello world".into(),
        blob: vec![1, 2, 3],
        plain: "left alone".into(),
    }
}

#[test]
fn a_fully_readable_record_opens_back_to_itself() {
    let p = Protector::new(Readable::policy(), Arc::new(OneKey)).unwrap();
    let original = readable();
    let sealed = original.seal(&p).unwrap();
    assert_eq!(sealed.clone().open(&p).unwrap(), original);

    // Under another row nothing opens.
    let mut moved = sealed.clone();
    moved.id = 43;
    assert!(matches!(moved.open(&p), Err(Error::Decrypt)));

    // An Option stays None through both directions.
    let mut none = original.clone();
    none.ssn = None;
    let sealed_none = none.seal(&p).unwrap();
    assert!(sealed_none.ssn.is_none());
    assert_eq!(sealed_none.open(&p).unwrap(), none);
}

#[test]
fn search_term_matches_the_stored_prefix() {
    let p = Protector::new(Readable::policy(), Arc::new(OneKey)).unwrap();
    let sealed = readable().seal(&p).unwrap();
    let term = Readable::email_term(&p, b"a@b.io").unwrap();
    assert_eq!(&sealed.email[..32], &term[..]);
}

#[test]
fn masked_applies_only_the_declared_masks() {
    let p = Protector::new(Readable::policy(), Arc::new(OneKey)).unwrap();
    let shown = readable().masked(&p).unwrap();
    assert_eq!(shown.phone, "********4567");
    assert_eq!(shown.note, "he*********");
    assert_eq!(shown.email, "a@b.io");
    assert_eq!(shown.ssn.as_deref(), Some("078-05-1120"));
}

#[test]
fn open_refuses_unsealed_values_unless_lenient() {
    let p = Protector::new(Readable::policy(), Arc::new(OneKey)).unwrap();
    let mut sealed = readable().seal(&p).unwrap();
    // A pre-migration plaintext left in the encrypted column.
    sealed.email = b"legacy@b.io".to_vec();
    assert!(matches!(sealed.clone().open(&p), Err(Error::Unprotected(_))));
    let opened = sealed.open_lenient(&p).unwrap();
    assert_eq!(opened.email, "legacy@b.io");
    assert_eq!(opened.phone, "555-123-4567", "the rest still opens");
}

#[test]
fn a_protector_built_from_a_different_policy_is_refused_not_trusted() {
    // The TOML says phone is encrypted; the struct says FPE. Sealing through
    // the struct must not produce bytes of the wrong shape silently.
    let policy: Policy = toml::from_str(
        "[[column]]\ntable = \"users\"\ncolumn = \"email\"\nsearchable = true\n\
         [[column]]\ntable = \"users\"\ncolumn = \"ssn\"\n\
         [[column]]\ntable = \"users\"\ncolumn = \"phone\"\n\
         [[column]]\ntable = \"users\"\ncolumn = \"note\"\ntransform = \"none\"\nmask = { keep_first = 2 }\n\
         [[column]]\ntable = \"users\"\ncolumn = \"blob\"\n\
         [[table]]\ntable = \"users\"\nrow_key = \"id\"\n",
    )
    .unwrap();
    let p = Protector::new(policy, Arc::new(OneKey)).unwrap();
    assert!(matches!(readable().seal(&p), Err(Error::Policy(_))));

    // And a column the protector does not know at all.
    let p = Protector::new(Event::policy(), Arc::new(OneKey)).unwrap();
    assert!(matches!(readable().seal(&p), Err(Error::UnknownColumn(_))));
}

#[test]
fn a_table_without_a_row_key_seals_cell_only() {
    let p = protector();
    let event = Event { seq: 1, payload: b"login".to_vec() };
    let sealed = event.seal(&p).unwrap();
    assert_eq!(&sealed.payload[..4], b"DBS2", "cell-bound envelope, no blind index");
    assert_eq!(sealed.open(&p).unwrap(), event);
}

#[test]
fn the_traits_are_implemented_for_generic_code() {
    fn round_trip<T: dbsec_core::record::Protect + PartialEq + std::fmt::Debug>(
        record: T,
        p: &Protector,
    ) {
        use dbsec_core::record::Sealed as _;
        let opened = record.seal(p).unwrap().open(p).unwrap();
        assert_eq!(opened, record);
    }
    let p = Protector::new(Readable::policy(), Arc::new(OneKey)).unwrap();
    round_trip(readable(), &p);
}
