//! Canonicalising a row's declared key so both data paths agree on it.
//!
//! A row key is bound into every row-bound envelope
//! ([`dbsec_core::envelope::RowKey`]), which means the write path and the read
//! path must derive *identical* bytes for the same row — across drivers, across
//! wire formats, and across the two directions.
//!
//! That is harder than it looks, and it is the reason this module exists rather
//! than the row key being passed around as raw wire bytes. PostgreSQL sends the
//! same value differently depending on what the client asked for: `id = 42` is
//! the two ASCII bytes `42` to a text-format client and four big-endian bytes
//! to a binary one. Both appear in this workspace's own e2e suite — psycopg
//! binds text, sqlx binds binary — so binding raw bytes would mean a row
//! written through one driver could not be read through the other. The failure
//! would look like data corruption and would depend on which library the client
//! happened to use.
//!
//! So a key is canonicalised through its *type* before it is bound, and the
//! canonical form is the value's ordinary text representation: `42`, not the
//! bytes that happened to carry it.
//!
//! # Why the supported set is small
//!
//! Every type here needs a decoder that agrees with PostgreSQL's own output
//! exactly, in both formats. That is a surface the proxy has deliberately
//! avoided elsewhere — the read path sniffs a `\x` prefix rather than consult a
//! type OID — so it is kept to the types people actually declare keys on, and
//! anything else is refused at startup with a message naming the column. An
//! unsupported type is a configuration error the operator can see, never a
//! silent fallback to raw bytes.

use dbsec_core::envelope::RowKey;

use crate::Error;

/// PostgreSQL type OIDs this module can canonicalise. From
/// `pg_catalog.pg_type`; these are stable across versions and are what the
/// catalog lookup returns in `atttypid`.
pub mod oid {
    pub const INT8: u32 = 20;
    pub const INT2: u32 = 21;
    pub const INT4: u32 = 23;
    pub const TEXT: u32 = 25;
    pub const VARCHAR: u32 = 1043;
    pub const UUID: u32 = 2950;
}

/// The wire format one value arrived in: 0 text, 1 binary, per the protocol's
/// format codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Binary,
}

impl Format {
    /// The protocol sends format codes as `i16`. Anything but 0 or 1 is
    /// undefined, and guessing at it would be guessing at the bytes of a value
    /// that decides where a ciphertext belongs.
    pub fn from_code(code: i16) -> Result<Self, Error> {
        match code {
            0 => Ok(Self::Text),
            1 => Ok(Self::Binary),
            other => Err(Error::RowKeyType(format!("unknown wire format code {other}"))),
        }
    }
}

/// Whether the proxy can canonicalise a key of this type. Checked once at
/// resolution time so the refusal names the column and happens at startup,
/// rather than once per row on the data path.
///
/// `bpchar` (`char(n)`) is deliberately absent. PostgreSQL blank-pads it to
/// `n` on *output* but the client's own input is not padded, so `'abc'` would
/// seal against `abc` and read back as `abc` followed by `n - 3` spaces. The
/// padding width lives in `atttypmod`, which this path does not carry, so the
/// two directions cannot be reconciled here — the column is refused at
/// resolution instead, where the operator can see it.
pub fn supported(type_oid: u32) -> bool {
    matches!(type_oid, oid::INT2 | oid::INT4 | oid::INT8 | oid::TEXT | oid::VARCHAR | oid::UUID)
}

/// The canonical bytes of one row key value.
///
/// `None` for a SQL NULL: a row whose key is NULL has no name, so nothing can
/// be bound to it. Callers turn that into a refusal rather than binding the
/// empty string, which every NULL-keyed row would share.
///
/// Text format is *not* trusted to be canonical. It is on the read path —
/// there it is PostgreSQL's own output — but the write path feeds this the raw
/// source text of a SQL literal and the client's own text-format Bind bytes,
/// and PostgreSQL accepts many spellings it never emits: `0042`, `+42` and
/// `' 42 '` all store as `42`, and a `uuid` may arrive uppercase, braced or
/// unhyphenated. So every type parses and re-renders in both formats, and a
/// value that does not parse is a refusal rather than a key that seals now and
/// fails to open later.
pub fn canonical(type_oid: u32, format: Format, value: Option<&[u8]>) -> Result<RowKey, Error> {
    let bytes = value.ok_or_else(|| Error::RowKeyType("row key is NULL".to_owned()))?;
    let text: Vec<u8> = match (type_oid, format) {
        (oid::INT2, Format::Text) => integer_text::<i16>(bytes)?,
        (oid::INT4, Format::Text) => integer_text::<i32>(bytes)?,
        (oid::INT8, Format::Text) => integer_text::<i64>(bytes)?,
        (oid::UUID, Format::Text) => uuid_from_text(bytes)?,
        // The only genuine pass-through: a `text`/`varchar` value is its own
        // canonical form in both directions, so it needs validating, not
        // reinterpreting.
        (oid::TEXT | oid::VARCHAR, Format::Text | Format::Binary) => {
            utf8(bytes)?.as_bytes().to_vec()
        }
        (oid::INT2, Format::Binary) => i16::from_be_bytes(fixed(bytes)?).to_string().into_bytes(),
        (oid::INT4, Format::Binary) => i32::from_be_bytes(fixed(bytes)?).to_string().into_bytes(),
        (oid::INT8, Format::Binary) => i64::from_be_bytes(fixed(bytes)?).to_string().into_bytes(),
        (oid::UUID, Format::Binary) => hyphenated(&hex::encode(fixed::<16>(bytes)?)).into_bytes(),
        // Reached in *both* formats. Letting text format fall through to the
        // raw bytes here would be the silent fallback this module's header
        // rules out, for exactly the types `supported` refuses at startup.
        (other, _) => {
            return Err(Error::RowKeyType(format!("type oid {other} cannot be a row key")))
        }
    };
    Ok(RowKey::new(text))
}

/// Row key bytes as a `&str`, or a refusal. Borrowed rather than owned: the
/// pass-through arms copy once into the key and never build a `String` on the
/// way (PERF-3).
fn utf8(bytes: &[u8]) -> Result<&str, Error> {
    std::str::from_utf8(bytes)
        .map_err(|_| Error::RowKeyType("row key is not valid UTF-8".to_owned()))
}

/// One integer's canonical text: parsed through its own type, then rendered
/// the way the server renders it.
///
/// Surrounding whitespace is trimmed because PostgreSQL accepts `' 42 '` as an
/// integer; everything else — a leading `+`, leading zeros, a value outside the
/// type's range — is [`std::str::FromStr`]'s call, and it agrees with the
/// server on all of them.
fn integer_text<T>(bytes: &[u8]) -> Result<Vec<u8>, Error>
where
    T: std::str::FromStr + std::fmt::Display,
{
    let text = utf8(bytes)?;
    match text.trim().parse::<T>() {
        Ok(n) => Ok(n.to_string().into_bytes()),
        Err(_) => Err(Error::RowKeyType(format!(
            "row key {text:?} is not an integer of its column's type"
        ))),
    }
}

/// One `uuid`'s canonical text, from any spelling PostgreSQL accepts on input:
/// upper or lower case, optionally brace-wrapped, and with the hyphens in the
/// standard places or absent entirely.
fn uuid_from_text(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let text = utf8(bytes)?;
    let refuse = || Error::RowKeyType(format!("row key {text:?} is not a uuid"));
    let inner = text.trim();
    let inner = inner.strip_prefix('{').map_or(inner, |rest| rest.strip_suffix('}').unwrap_or(""));
    let mut hex = String::with_capacity(32);
    for ch in inner.chars() {
        if ch == '-' {
            continue;
        }
        if !ch.is_ascii_hexdigit() {
            return Err(refuse());
        }
        hex.push(ch.to_ascii_lowercase());
    }
    if hex.len() != 32 {
        return Err(refuse());
    }
    Ok(hyphenated(&hex).into_bytes())
}

/// A binary integer must be exactly its type's width. A short or long body is a
/// malformed frame, not a value to reinterpret.
fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| {
        Error::RowKeyType(format!("row key body is {} bytes, expected {N}", bytes.len()))
    })
}

/// PostgreSQL's `uuid` output form: lowercase hex, hyphenated 8-4-4-4-12.
/// `hex` is exactly 32 lowercase hex digits; both callers guarantee that.
fn hyphenated(hex: &str) -> String {
    debug_assert_eq!(hex.len(), 32, "uuid hex is 32 digits");
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole module exists for: the same row, bound the same
    /// way, whichever format the client chose. A failure here means a row
    /// written through psycopg cannot be read through sqlx.
    #[test]
    fn text_and_binary_forms_canonicalise_identically() {
        let cases: &[(u32, &[u8], &[u8], &str)] = &[
            (oid::INT2, b"42", &42i16.to_be_bytes(), "42"),
            (oid::INT4, b"42", &42i32.to_be_bytes(), "42"),
            (oid::INT8, b"42", &42i64.to_be_bytes(), "42"),
            (oid::INT4, b"-7", &(-7i32).to_be_bytes(), "-7"),
            (oid::INT8, b"9223372036854775807", &i64::MAX.to_be_bytes(), "9223372036854775807"),
            (oid::TEXT, b"alice", b"alice", "alice"),
        ];
        for (type_oid, text, binary, expected) in cases {
            let from_text = canonical(*type_oid, Format::Text, Some(text)).expect("text");
            let from_binary = canonical(*type_oid, Format::Binary, Some(binary)).expect("binary");
            assert_eq!(from_text, from_binary, "type {type_oid} disagrees across formats");
            assert_eq!(from_text.as_bytes(), expected.as_bytes());
        }
    }

    #[test]
    fn a_binary_uuid_matches_its_text_form() {
        let bytes: [u8; 16] = [
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ];
        let text = b"550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            canonical(oid::UUID, Format::Binary, Some(&bytes)).unwrap(),
            canonical(oid::UUID, Format::Text, Some(text)).unwrap()
        );
    }

    /// A NULL key names no row, and the empty string would be shared by every
    /// NULL-keyed row — which is exactly the collision row binding prevents.
    #[test]
    fn a_null_row_key_is_refused_rather_than_bound_as_empty() {
        assert!(matches!(canonical(oid::INT4, Format::Text, None), Err(Error::RowKeyType(_))));
    }

    #[test]
    fn a_wrong_width_binary_integer_is_refused() {
        assert!(matches!(
            canonical(oid::INT4, Format::Binary, Some(&[0, 0, 42])),
            Err(Error::RowKeyType(_))
        ));
    }

    #[test]
    fn unsupported_types_are_named_not_guessed() {
        assert!(!supported(1114), "timestamp is not a supported row key type");
        assert!(matches!(
            canonical(1114, Format::Binary, Some(&[0; 8])),
            Err(Error::RowKeyType(_))
        ));
        // The text arm used to match any OID and pass the bytes through, so an
        // unsupported type was silently keyed on its raw wire form — the one
        // outcome the module header rules out (SEC-11).
        assert!(matches!(
            canonical(1114, Format::Text, Some(b"2026-08-19 08:00:00")),
            Err(Error::RowKeyType(_))
        ));
        assert!(matches!(Format::from_code(7), Err(Error::RowKeyType(_))));
    }

    /// The write path hands `canonical` a client's spelling, not the server's
    /// output. Every spelling PostgreSQL stores as `42` has to canonicalise to
    /// the `42` the read path will get back, or the row seals and never opens.
    #[test]
    fn integer_text_spellings_normalise_to_the_servers_output() {
        for spelling in [&b"42"[..], b"0042", b"+42", b" 42 ", b"\t42\n"] {
            let key = canonical(oid::INT4, Format::Text, Some(spelling)).expect("integer");
            assert_eq!(key.as_bytes(), b"42", "{:?} did not normalise", spelling.escape_ascii());
        }
        assert_eq!(canonical(oid::INT8, Format::Text, Some(b"-0007")).unwrap().as_bytes(), b"-7");
    }

    #[test]
    fn a_text_integer_that_is_not_an_integer_is_refused() {
        for bad in [&b"4 2"[..], b"", b"9223372036854775808", b"1_000", b"0x2a", b"nan"] {
            assert!(
                matches!(canonical(oid::INT8, Format::Text, Some(bad)), Err(Error::RowKeyType(_))),
                "{:?} was accepted as an int8 row key",
                bad.escape_ascii()
            );
        }
        // Out of range for the *column's* type, not just for any integer.
        assert!(matches!(
            canonical(oid::INT2, Format::Text, Some(b"40000")),
            Err(Error::RowKeyType(_))
        ));
    }

    /// PostgreSQL's `uuid` input is case- and format-insensitive; its output
    /// never is. Both directions have to land on the output form.
    #[test]
    fn uuid_text_spellings_normalise_to_the_servers_output() {
        let canonical_form = b"550e8400-e29b-41d4-a716-446655440000";
        for spelling in [
            &b"550E8400-E29B-41D4-A716-446655440000"[..],
            b"{550e8400-e29b-41d4-a716-446655440000}",
            b"550e8400e29b41d4a716446655440000",
            b"{550E8400E29B41D4A716446655440000}",
            b" 550e8400-e29b-41d4-a716-446655440000 ",
        ] {
            let key = canonical(oid::UUID, Format::Text, Some(spelling)).expect("uuid");
            assert_eq!(
                key.as_bytes(),
                canonical_form,
                "{:?} did not normalise",
                spelling.escape_ascii()
            );
        }
    }

    #[test]
    fn a_text_uuid_that_is_not_a_uuid_is_refused() {
        for bad in [
            &b"550e8400-e29b-41d4-a716-44665544000"[..], // 31 digits
            b"550e8400-e29b-41d4-a716-4466554400000",    // 33 digits
            b"550e8400-e29b-41d4-a716-44665544zzzz",
            b"{550e8400e29b41d4a716446655440000",
            b"",
        ] {
            assert!(
                matches!(canonical(oid::UUID, Format::Text, Some(bad)), Err(Error::RowKeyType(_))),
                "{:?} was accepted as a uuid row key",
                bad.escape_ascii()
            );
        }
    }

    /// `char(n)` is blank-padded by the server on output and not by the client
    /// on input, so `'abc'` would seal against `abc` and read back as
    /// `abc` plus padding. The pad width is not on this path, so the column is
    /// refused at resolution rather than canonicalised two different ways.
    #[test]
    fn bpchar_is_refused_rather_than_padded_one_way() {
        const BPCHAR: u32 = 1042;
        assert!(!supported(BPCHAR), "char(n) cannot be a row key");
        assert!(matches!(canonical(BPCHAR, Format::Text, Some(b"abc")), Err(Error::RowKeyType(_))));
        assert!(matches!(
            canonical(BPCHAR, Format::Binary, Some(b"abc")),
            Err(Error::RowKeyType(_))
        ));
    }

    /// `text` is the one type whose value is its own canonical form, so
    /// nothing about it may be trimmed, folded or reinterpreted.
    #[test]
    fn a_text_key_is_passed_through_exactly() {
        for value in [&b" padded "[..], b"MiXeD", b"0042", b""] {
            for format in [Format::Text, Format::Binary] {
                let key = canonical(oid::TEXT, format, Some(value)).expect("text");
                assert_eq!(key.as_bytes(), value);
            }
        }
    }
}
