//! The Bind-time array codec for `col = ANY($n)`.
//!
//! The SQL rewrite turns that predicate into a blind-index match, which means
//! the bound array has to be decoded, every element replaced by its index, and
//! the array re-encoded — in whichever of the two wire formats the client sent.
//!
//! Everything here parses bytes the client chose, so it is written to fail
//! rather than guess: an element count or a length that does not fit the body
//! yields `None`, and the caller treats that as "this array cannot be indexed
//! faithfully" rather than indexing part of it.

use std::sync::Arc;

use dbsec_core::transform::{FieldTransform, WireForm};
use sqlparser::ast::{Expr, Value};

use super::{column_ref, placeholder_index, text_plaintext, unwrap_casts, TableScope};
use crate::Error;

/// PostgreSQL's `bytea` type OID. The blind index prefix is BYTEA whatever the
/// column's own stored form is, so a re-encoded `= ANY($n)` array is a
/// `bytea[]` — the same element type the `ARRAY[...]` rewrite produces.
const BYTEA_OID: i32 = 17;

/// Element type OIDs whose binary form *is* the plaintext bytes, and which can
/// therefore be blind-indexed element by element: bytea, and the string types.
/// Anything else — an int, a timestamp, a composite — is not a value this
/// proxy ever sealed, so its array is left alone rather than turned into a
/// query that matches the wrong rows.
const INDEXABLE_ELEMENT_OIDS: [i32; 6] = [
    BYTEA_OID, // bytea
    19,        // name
    25,        // text
    705,       // unknown
    1042,      // bpchar
    1043,      // varchar
];

/// Most elements one `= ANY($n)` array may carry. A Bind body is bounded at
/// 1 GiB, which is room for hundreds of millions of empty elements and one
/// HMAC each; this caps the work a single parameter can ask for (SEC-33).
/// Real multi-value lookups are orders of magnitude below it, and an array
/// over the cap falls back to the refusal rather than being indexed.
const MAX_ARRAY_ELEMENTS: usize = 65_536;

/// One decoded `= ANY($n)` array parameter.
pub(super) struct BoundArray {
    /// Element plaintexts, `None` for a NULL element.
    elements: Vec<Option<Vec<u8>>>,
    /// The array's lower bound, preserved so the re-encoded array is the same
    /// array with different values in it.
    lower_bound: i32,
}

/// Replaces every element of a bound `= ANY($n)` array with its blind index
/// and re-encodes it as `bytea[]` in the parameter's own format, which is what
/// makes `substring(col from 1 for 32) = ANY($n)` match the stored rows.
///
/// `Ok(None)` is the fallback for anything this cannot do faithfully — a
/// parameter that is not a one-dimensional array, an element type that is not
/// a plaintext the proxy seals, an array over [`MAX_ARRAY_ELEMENTS`] — and the
/// caller turns it into the same [`Unprotected::Predicate`] signal the SQL
/// rewrite raises. Nothing partially indexed is ever produced: half the
/// elements matching the index and half the stored form is a *valid* query
/// that silently returns the wrong rows.
///
/// A NULL element stays NULL: `x = ANY(...)` is never true for one, so it
/// changes no row either way.
pub(super) fn index_array(
    value: &[u8],
    binary: bool,
    transform: &Arc<dyn FieldTransform>,
) -> Result<Option<Vec<u8>>, Error> {
    let decoded = if binary {
        decode_binary_array(value)
    } else {
        decode_text_array(value, transform.wire())
    };
    let Some(array) = decoded else { return Ok(None) };
    let mut indexed = Vec::with_capacity(array.elements.len());
    for element in &array.elements {
        let Some(plaintext) = element else {
            indexed.push(None);
            continue;
        };
        let Some(token) = transform.search_index(plaintext)? else { return Ok(None) };
        indexed.push(Some(token));
    }
    Ok(if binary {
        encode_binary_array(&indexed, array.lower_bound)
    } else {
        Some(encode_text_array(&indexed))
    })
}

/// Decodes the binary array format: `ndim | flags | element oid`, then one
/// `length | lower bound` pair per dimension, then each element as
/// `length | bytes` with `-1` for NULL. Every field is checked against what is
/// actually there — this is client-supplied and the only thing that has
/// validated it so far is nothing (SEC-11).
pub(super) fn decode_binary_array(mut raw: &[u8]) -> Option<BoundArray> {
    let ndim = take_i32(&mut raw)?;
    let _flags = take_i32(&mut raw)?;
    let element_oid = take_i32(&mut raw)?;
    if !INDEXABLE_ELEMENT_OIDS.contains(&element_oid) {
        return None;
    }
    match ndim {
        // No dimensions at all is the canonical empty array.
        0 => return raw.is_empty().then(|| BoundArray { elements: Vec::new(), lower_bound: 1 }),
        1 => {}
        _ => return None,
    }
    let count = take_i32(&mut raw)?;
    let lower_bound = take_i32(&mut raw)?;
    let count = usize::try_from(count).ok().filter(|count| *count <= MAX_ARRAY_ELEMENTS)?;
    let mut elements = Vec::new();
    for _ in 0..count {
        let size = take_i32(&mut raw)?;
        if size == -1 {
            elements.push(None);
            continue;
        }
        let size = usize::try_from(size).ok()?;
        if raw.len() < size {
            return None;
        }
        let (element, rest) = raw.split_at(size);
        elements.push(Some(element.to_vec()));
        raw = rest;
    }
    // Trailing bytes mean the message was not the array it claimed to be.
    raw.is_empty().then_some(BoundArray { elements, lower_bound })
}

/// Takes one big-endian `i32`, or `None` when fewer than four bytes are left.
fn take_i32(buf: &mut &[u8]) -> Option<i32> {
    if buf.len() < 4 {
        return None;
    }
    let (head, rest) = buf.split_at(4);
    *buf = rest;
    Some(i32::from_be_bytes(head.try_into().ok()?))
}

/// Decodes the text array format: `{a,"b c",NULL}`, where an element may be
/// double-quoted and a backslash escapes the character after it — in a quoted
/// element *and* in a bare one, which is what `array_in` does and what makes
/// `{a\,b}` one element rather than two. Only a flat, one-dimensional array is
/// accepted — a nested array or an explicit `[1:2]=` dimension prefix falls
/// back rather than being guessed at.
///
/// Getting the escaping wrong here is not a parse failure that shows up as
/// one: a mis-split element re-encodes into a perfectly well-formed `bytea[]`
/// of blind indexes for values nobody ever stored, so the statement quietly
/// returns the wrong rows. That is the outcome [`index_array`] exists to make
/// impossible, so anything this cannot decode faithfully returns `None` and
/// takes the `on_unprotected` path instead of guessing.
pub(super) fn decode_text_array(raw: &[u8], wire: WireForm) -> Option<BoundArray> {
    let text = std::str::from_utf8(raw).ok()?.trim();
    let body = text.strip_prefix('{')?.strip_suffix('}')?;
    let mut elements: Vec<Option<Vec<u8>>> = Vec::new();
    if body.trim().is_empty() {
        return Some(BoundArray { elements, lower_bound: 1 });
    }
    let bytes = body.as_bytes();
    let mut at = 0;
    loop {
        while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        let element = if bytes.get(at) == Some(&b'"') {
            at += 1;
            let mut value = Vec::new();
            loop {
                match *bytes.get(at)? {
                    b'\\' => {
                        value.push(*bytes.get(at + 1)?);
                        at += 2;
                    }
                    b'"' => {
                        at += 1;
                        break;
                    }
                    byte => {
                        value.push(byte);
                        at += 1;
                    }
                }
            }
            Some(String::from_utf8(value).ok()?)
        } else {
            // An unquoted element escapes with a backslash exactly as a quoted
            // one does — `array_in` does not restrict escaping to quotes — so
            // `{a\,b}` is the single element `a,b` and not two elements. Scanning
            // to the next raw comma instead would split it there and hand both
            // halves to the blind index, which matches nothing anyone stored.
            let mut value = Vec::new();
            let mut escaped = false;
            // Only *unescaped* trailing whitespace is insignificant; `a\ ` ends
            // in a space that is part of the value.
            let mut trailing_space = 0;
            loop {
                match bytes.get(at) {
                    None | Some(b',') => break,
                    Some(b'\\') => {
                        value.push(*bytes.get(at + 1)?);
                        at += 2;
                        escaped = true;
                        trailing_space = 0;
                    }
                    // An unescaped brace is a nested array, which this does not
                    // handle; an escaped one is just a character.
                    Some(b'{' | b'}') => return None,
                    Some(&byte) => {
                        value.push(byte);
                        at += 1;
                        if byte.is_ascii_whitespace() {
                            trailing_space += 1;
                        } else {
                            trailing_space = 0;
                        }
                    }
                }
            }
            value.truncate(value.len() - trailing_space);
            let unquoted = String::from_utf8(value).ok()?;
            // `NULL` is the null element only unquoted and unescaped: `\N ULL`
            // and `"NULL"` are both the four-character string.
            (escaped || !unquoted.eq_ignore_ascii_case("null")).then_some(unquoted)
        };
        elements.push(element.map(|text| text_plaintext(&text, wire)));
        if elements.len() > MAX_ARRAY_ELEMENTS {
            return None;
        }
        while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        match bytes.get(at) {
            None => break,
            Some(b',') => at += 1,
            Some(_) => return None,
        }
    }
    Some(BoundArray { elements, lower_bound: 1 })
}

/// Re-encodes indexed elements in the binary array format. `None` only when
/// the element count does not fit the protocol's `i32` — impossible under
/// [`MAX_ARRAY_ELEMENTS`], and checked rather than cast so it stays impossible
/// if that cap ever moves (SEC-15).
pub(super) fn encode_binary_array(
    elements: &[Option<Vec<u8>>],
    lower_bound: i32,
) -> Option<Vec<u8>> {
    let count = i32::try_from(elements.len()).ok()?;
    let has_null = elements.iter().any(Option::is_none);
    let payload: usize = elements.iter().flatten().map(Vec::len).sum();
    let mut out = Vec::with_capacity(20 + elements.len() * 4 + payload);
    out.extend_from_slice(&if elements.is_empty() { 0i32 } else { 1i32 }.to_be_bytes());
    out.extend_from_slice(&i32::from(has_null).to_be_bytes());
    out.extend_from_slice(&BYTEA_OID.to_be_bytes());
    if elements.is_empty() {
        return Some(out);
    }
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&lower_bound.to_be_bytes());
    for element in elements {
        match element {
            None => out.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(token) => {
                let size = i32::try_from(token.len()).ok()?;
                out.extend_from_slice(&size.to_be_bytes());
                out.extend_from_slice(token);
            }
        }
    }
    Some(out)
}

/// Re-encodes indexed elements as an array literal. Each element is bytea's
/// `\x` hex input syntax, quoted — and inside a quoted array element the
/// backslash itself has to be escaped, or the array parser eats it.
pub(super) fn encode_text_array(elements: &[Option<Vec<u8>>]) -> Vec<u8> {
    let mut out = String::from("{");
    for (position, element) in elements.iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        match element {
            None => out.push_str("NULL"),
            Some(token) => {
                out.push_str("\"\\\\x");
                out.push_str(&hex::encode(token));
                out.push('"');
            }
        }
    }
    out.push('}');
    out.into_bytes()
}

/// The parameter index and transform behind `col = ANY($n)`, when `col` is a
/// searchable column and the right operand is one bound array parameter.
/// `None` for every other shape — `= ANY(SELECT ...)`, an array expression, a
/// non-searchable column — which the caller signals as an unsupported
/// predicate exactly as before.
pub(super) fn array_parameter(
    column: &Expr,
    array: &Expr,
    scope: &TableScope<'_>,
) -> Option<(usize, Arc<dyn FieldTransform>)> {
    let transform = column_ref(scope, column).filter(|t| t.supports_search())?.clone();
    let Expr::Value(Value::Placeholder(placeholder)) = unwrap_casts(array) else { return None };
    Some((placeholder_index(placeholder)?, transform))
}

#[cfg(test)]
pub(in crate::encrypt) mod tests {
    use super::*;
    use proptest::prelude::*;

    use crate::rows::tests::transform;
    use dbsec_core::blind_index;

    /// A binary-format array parameter: `ndim | flags | element oid`, one
    /// `length | lower bound` pair, then `length | bytes` per element.
    pub(in crate::encrypt) fn binary_array(
        element_oid: i32,
        elements: &[Option<&[u8]>],
    ) -> Vec<u8> {
        let mut out = 1i32.to_be_bytes().to_vec();
        out.extend_from_slice(&i32::from(elements.iter().any(Option::is_none)).to_be_bytes());
        out.extend_from_slice(&element_oid.to_be_bytes());
        out.extend_from_slice(&(elements.len() as i32).to_be_bytes());
        out.extend_from_slice(&1i32.to_be_bytes());
        for element in elements {
            match element {
                None => out.extend_from_slice(&(-1i32).to_be_bytes()),
                Some(bytes) => {
                    out.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                    out.extend_from_slice(bytes);
                }
            }
        }
        out
    }

    #[test]
    fn the_array_codec_reads_what_postgres_writes_and_refuses_the_rest() {
        let elements = |array: BoundArray| array.elements;
        // Quoted elements escape `"` and `\`; unquoted NULL is a NULL element.
        let text = decode_text_array(br#"{ "a,b" , plain , NULL , "q\"\\x" }"#, WireForm::Text)
            .expect("a flat array");
        assert_eq!(
            elements(text),
            [Some(b"a,b".to_vec()), Some(b"plain".to_vec()), None, Some(b"q\"\\x".to_vec()),]
        );
        // A backslash escapes the next character in a *bare* element too, so
        // `{a\,b}` is one element and not two. Splitting on the raw comma would
        // index two values nobody stored and quietly return the wrong rows.
        assert_eq!(
            elements(decode_text_array(br"{a\,b}", WireForm::Text).unwrap()),
            [Some(b"a,b".to_vec())]
        );
        // Escaping also decides what is NULL and what is the string "NULL",
        // and keeps whitespace a bare element would otherwise have trimmed.
        assert_eq!(
            elements(decode_text_array(br"{\NULL,NULL,a\ }", WireForm::Text).unwrap()),
            [Some(b"NULL".to_vec()), None, Some(b"a ".to_vec())]
        );
        // A BYTEA-form column reads `\x` as hex input, the same as a literal —
        // which on the wire needs the backslash escaped, exactly as PostgreSQL
        // writes it back out. One backslash escapes the `x` instead, leaving a
        // bare `x616263` that is not hex input at all.
        assert_eq!(
            elements(decode_text_array(br"{\\x616263}", WireForm::Bytea).unwrap()),
            [Some(b"abc".to_vec())]
        );
        assert_eq!(
            elements(decode_text_array(br"{\x616263}", WireForm::Bytea).unwrap()),
            [Some(b"x616263".to_vec())]
        );
        assert!(decode_text_array(b"{}", WireForm::Text).unwrap().elements.is_empty());
        for refused in [&b"{a,b"[..], b"a,b}", b"{{a},{b}}", b"[1:1]={a}", b"{a} trailing"] {
            assert!(decode_text_array(refused, WireForm::Text).is_none(), "{refused:?}");
        }

        // Binary: only element types whose bytes are the plaintext.
        let array = decode_binary_array(&binary_array(25, &[Some(b"a"), None])).expect("a text[]");
        assert_eq!(array.lower_bound, 1);
        assert_eq!(elements(array), [Some(b"a".to_vec()), None]);
        assert!(decode_binary_array(&binary_array(23, &[Some(b"\0\0\0\x01")])).is_none());
        assert!(decode_binary_array(b"").is_none());
        // Trailing bytes mean it was not the array it claimed to be.
        let mut trailing = binary_array(17, &[Some(b"a")]);
        trailing.push(0);
        assert!(decode_binary_array(&trailing).is_none());
        // An element length past the end of the message.
        let mut lying = binary_array(17, &[Some(b"a")]);
        let last = lying.len() - 5;
        lying[last..last + 4].copy_from_slice(&99i32.to_be_bytes());
        assert!(decode_binary_array(&lying).is_none());
    }

    /// Element bytes drawn from the array format's own metacharacters — the
    /// quote, the escape, the braces, the separator, the NULL spelling — so a
    /// generated array actually reaches the branches that decide where one
    /// element ends and the next begins. Uniformly random bytes would spend
    /// almost every case being rejected by the first field.
    fn array_element() -> impl Strategy<Value = Option<Vec<u8>>> {
        let byte = prop::sample::select(vec![
            b'a', b'N', b'U', b'L', b'x', b',', b'"', b'\\', b'{', b'}', b' ', 0x00, 0xff,
        ]);
        prop::option::of(prop::collection::vec(byte, 0..6))
    }

    /// Wire bytes for a `= ANY($n)` parameter: arbitrary noise, both encoders'
    /// own output, and text literals assembled straight out of the format's
    /// metacharacters — the shapes no encoder produces but a client can send.
    fn array_bytes() -> impl Strategy<Value = Vec<u8>> {
        let metacharacters = prop::sample::select(vec![
            "a", ",", "\"", "\\", "{", "}", " ", "NULL", "\\x61", "\\\\x61",
        ]);
        prop_oneof![
            prop::collection::vec(any::<u8>(), 0..64),
            prop::collection::vec(array_element(), 0..6)
                .prop_map(|elements| encode_binary_array(&elements, 1).expect("encodes")),
            prop::collection::vec(array_element(), 0..6)
                .prop_map(|elements| encode_text_array(&elements)),
            prop::collection::vec(metacharacters, 0..8).prop_map(|parts| format!(
                "{{{}}}",
                parts.concat()
            )
            .into_bytes()),
        ]
    }

    proptest! {
        /// Re-encoding what was decoded is the whole codec's contract: a
        /// `= ANY($n)` array goes out as the same array with blind indexes in
        /// it, so every element the decoder produced has to survive the
        /// encoder unchanged, NULLs and element boundaries included.
        #[test]
        fn the_array_codec_round_trips_every_element(
            elements in prop::collection::vec(array_element(), 0..8),
        ) {
            let binary = encode_binary_array(&elements, 1).expect("encodes");
            let decoded = decode_binary_array(&binary).expect("decodes its own output");
            prop_assert_eq!(&decoded.elements, &elements);

            // The text encoder writes bytea `\x` hex, which is how the text
            // decoder reads a BYTEA-form column back — whatever bytes it holds.
            let text = encode_text_array(&elements);
            let decoded =
                decode_text_array(&text, WireForm::Bytea).expect("decodes its own output");
            prop_assert_eq!(&decoded.elements, &elements);
        }

        /// Both decoders read bytes a client chose, in a session task that
        /// owns the connection: a panic here is that client crashing its own
        /// session, and an index or slice off the end of a truncated array is
        /// the easiest way to write one.
        #[test]
        fn the_array_decoders_never_panic_on_arbitrary_bytes(raw in array_bytes()) {
            let _ = decode_binary_array(&raw);
            let _ = decode_text_array(&raw, WireForm::Text);
            let _ = decode_text_array(&raw, WireForm::Bytea);
        }

        /// The same, on inputs that started out well-formed. Corrupting one
        /// byte of a real encoding is what reaches the states past the header
        /// — a length field that now overruns, a quote that never closes.
        #[test]
        fn a_corrupted_array_is_rejected_but_never_panics(
            elements in prop::collection::vec(array_element(), 0..6),
            at in any::<prop::sample::Index>(),
            patch in any::<u8>(),
        ) {
            let mut binary = encode_binary_array(&elements, 1).expect("encodes");
            let index = at.index(binary.len());
            binary[index] = patch;
            let _ = decode_binary_array(&binary);

            let mut text = encode_text_array(&elements);
            let index = at.index(text.len());
            text[index] = patch;
            let _ = decode_text_array(&text, WireForm::Bytea);
        }

        /// The fail-closed contract [`index_array`] exists to keep: either the
        /// parameter is refused whole — `None`, which the caller turns into
        /// the same `on_unprotected` signal the SQL rewrite raises — or every
        /// element is the blind index of the element that was there, with the
        /// NULLs still in their places. A half-indexed array is not a broken
        /// message the backend rejects; it is a *valid* query that silently
        /// returns the wrong rows.
        #[test]
        fn an_indexed_array_is_all_or_nothing(raw in array_bytes(), binary in any::<bool>()) {
            use crate::rows::tests::INDEX_KEY;

            let transform = transform(true);
            let decoded = if binary {
                decode_binary_array(&raw)
            } else {
                decode_text_array(&raw, transform.wire())
            };
            let indexed = index_array(&raw, binary, &transform).expect("indexing cannot fail");

            let Some(array) = decoded else {
                prop_assert!(indexed.is_none(), "an undecodable array must not be indexed");
                return Ok(());
            };
            let indexed = indexed.expect("a decodable array is indexed");
            let reread = if binary {
                decode_binary_array(&indexed)
            } else {
                decode_text_array(&indexed, WireForm::Bytea)
            }
            .expect("the indexed array is itself a well-formed array");

            prop_assert_eq!(reread.elements.len(), array.elements.len(), "element count moved");
            for (before, after) in array.elements.iter().zip(&reread.elements) {
                match (before, after) {
                    (None, None) => {}
                    (Some(plaintext), Some(token)) => prop_assert_eq!(
                        token,
                        &blind_index::compute(&INDEX_KEY, plaintext).to_vec(),
                        "an element is not its own blind index"
                    ),
                    _ => prop_assert!(false, "a NULL element changed places"),
                }
            }
        }
    }
}
