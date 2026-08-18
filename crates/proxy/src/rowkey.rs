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
    pub const BPCHAR: u32 = 1042;
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
pub fn supported(type_oid: u32) -> bool {
    matches!(
        type_oid,
        oid::INT2 | oid::INT4 | oid::INT8 | oid::TEXT | oid::BPCHAR | oid::VARCHAR | oid::UUID
    )
}

/// The canonical bytes of one row key value.
///
/// `None` for a SQL NULL: a row whose key is NULL has no name, so nothing can
/// be bound to it. Callers turn that into a refusal rather than binding the
/// empty string, which every NULL-keyed row would share.
pub fn canonical(type_oid: u32, format: Format, value: Option<&[u8]>) -> Result<RowKey, Error> {
    let bytes = value.ok_or_else(|| Error::RowKeyType("row key is NULL".to_owned()))?;
    let text = match (type_oid, format) {
        // Text format is already PostgreSQL's own output for every type here,
        // so it is the canonical form by construction and needs only to be
        // valid UTF-8 (which `text`, `uuid` and integer output all are).
        (_, Format::Text) => std::str::from_utf8(bytes)
            .map_err(|_| Error::RowKeyType("row key is not valid UTF-8".to_owned()))?
            .to_owned(),
        (oid::INT2, Format::Binary) => i16::from_be_bytes(fixed(bytes)?).to_string(),
        (oid::INT4, Format::Binary) => i32::from_be_bytes(fixed(bytes)?).to_string(),
        (oid::INT8, Format::Binary) => i64::from_be_bytes(fixed(bytes)?).to_string(),
        (oid::UUID, Format::Binary) => uuid_text(bytes)?,
        (oid::TEXT | oid::BPCHAR | oid::VARCHAR, Format::Binary) => std::str::from_utf8(bytes)
            .map_err(|_| Error::RowKeyType("row key is not valid UTF-8".to_owned()))?
            .to_owned(),
        (other, Format::Binary) => {
            return Err(Error::RowKeyType(format!("type oid {other} cannot be a row key")))
        }
    };
    Ok(RowKey::new(text.into_bytes()))
}

/// A binary integer must be exactly its type's width. A short or long body is a
/// malformed frame, not a value to reinterpret.
fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| {
        Error::RowKeyType(format!("row key body is {} bytes, expected {N}", bytes.len()))
    })
}

/// PostgreSQL's `uuid` output form: lowercase hex, hyphenated 8-4-4-4-12.
fn uuid_text(bytes: &[u8]) -> Result<String, Error> {
    let b: [u8; 16] = fixed(bytes)?;
    let hex = hex::encode(b);
    Ok(format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]))
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
        assert!(matches!(Format::from_code(7), Err(Error::RowKeyType(_))));
    }
}
