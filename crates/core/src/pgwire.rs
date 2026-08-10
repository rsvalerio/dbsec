//! Sans-io framing for the PostgreSQL v3 wire protocol.
//!
//! Only what the proxy needs: startup-phase classification and regular message
//! headers. Kept free of I/O so it can be property-tested and fuzzed directly
//! (milestone 10).
//!
//! Startup messages have no type byte: `i32 length (incl. itself) | i32 code | ...`.
//! Every later message is `u8 type | i32 length (incl. itself, excl. type) | body`.

use crate::Error;

pub const PROTOCOL_V3: i32 = 3 << 16;
pub const SSL_REQUEST: i32 = 80877103;
pub const GSSENC_REQUEST: i32 = 80877104;
pub const CANCEL_REQUEST: i32 = 80877102;

/// Startup header: i32 length + i32 code.
pub const STARTUP_HEADER_LEN: usize = 8;
/// Regular header: type byte + i32 length.
pub const FRAME_HEADER_LEN: usize = 5;

/// Largest message we accept; matches Postgres' own 1 GiB limit.
pub const MAX_MESSAGE_LEN: usize = 1 << 30;

/// What the client opened the connection with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Startup {
    /// SSLRequest — answer `S`/`N` locally, never forward.
    Tls,
    /// GSSENCRequest — we don't support GSSAPI encryption; answer `N`.
    GssEnc,
    /// CancelRequest — forward upstream, then both sides close.
    Cancel,
    /// StartupMessage with a protocol version (v3 or otherwise; the server
    /// rejects versions it doesn't speak, so we just forward).
    Protocol(i32),
}

pub fn startup_kind(code: i32) -> Startup {
    match code {
        SSL_REQUEST => Startup::Tls,
        GSSENC_REQUEST => Startup::GssEnc,
        CANCEL_REQUEST => Startup::Cancel,
        version => Startup::Protocol(version),
    }
}

/// Validates a startup-message length field and returns the number of bytes
/// that follow it (code + payload).
pub fn startup_body_len(len_field: [u8; 4]) -> Result<usize, Error> {
    let len = i32::from_be_bytes(len_field);
    if len < STARTUP_HEADER_LEN as i32 || len as usize > MAX_MESSAGE_LEN {
        return Err(Error::BadMessageLength(len));
    }
    Ok(len as usize - 4)
}

/// Validates a regular-message header and returns `(type, body length)`.
pub fn frame_body_len(header: &[u8; FRAME_HEADER_LEN]) -> Result<(u8, usize), Error> {
    let mut len_field = [0u8; 4];
    len_field.copy_from_slice(&header[1..]);
    let len = i32::from_be_bytes(len_field);
    if len < 4 || len as usize > MAX_MESSAGE_LEN {
        return Err(Error::BadMessageLength(len));
    }
    Ok((header[0], len as usize - 4))
}

/// One field of a RowDescription ('T') message; only what the decrypt path
/// needs to match configured columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowField {
    /// OID of the table the column comes from; 0 for computed columns.
    pub table_oid: u32,
    /// Attribute number within the table; 0 for computed columns.
    pub attnum: i16,
}

/// Parses a RowDescription ('T') body.
pub fn parse_row_description(mut body: &[u8]) -> Result<Vec<RowField>, Error> {
    let count = take_i16(&mut body)?;
    let mut fields = Vec::with_capacity(count.max(0) as usize);
    for _ in 0..count {
        skip_cstr(&mut body)?;
        let table_oid = u32::from_be_bytes(take(&mut body, 4)?.try_into().expect("4 bytes"));
        let attnum = take_i16(&mut body)?;
        // Type OID (4), type length (2), type modifier (4), format code (2).
        take(&mut body, 12)?;
        fields.push(RowField { table_oid, attnum });
    }
    if !body.is_empty() {
        return Err(Error::MalformedBackend);
    }
    Ok(fields)
}

/// Parses a DataRow ('D') body into per-column values (`None` = SQL NULL).
pub fn parse_data_row(mut body: &[u8]) -> Result<Vec<Option<&[u8]>>, Error> {
    let count = take_i16(&mut body)?;
    let mut values = Vec::with_capacity(count.max(0) as usize);
    for _ in 0..count {
        let len = i32::from_be_bytes(take(&mut body, 4)?.try_into().expect("4 bytes"));
        match len {
            -1 => values.push(None),
            0.. => values.push(Some(take(&mut body, len as usize)?)),
            _ => return Err(Error::MalformedBackend),
        }
    }
    if !body.is_empty() {
        return Err(Error::MalformedBackend);
    }
    Ok(values)
}

/// Encodes a DataRow ('D') body from per-column values.
pub fn encode_data_row(values: &[Option<std::borrow::Cow<'_, [u8]>>]) -> Vec<u8> {
    let payload: usize = values.iter().map(|v| v.as_ref().map_or(0, |v| v.len())).sum();
    let mut out = Vec::with_capacity(2 + values.len() * 4 + payload);
    out.extend_from_slice(&(values.len() as i16).to_be_bytes());
    for value in values {
        match value {
            None => out.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(v) => {
                out.extend_from_slice(&(v.len() as i32).to_be_bytes());
                out.extend_from_slice(v);
            }
        }
    }
    out
}

/// A parsed Parse ('P') message: statement name, query text, and the raw
/// parameter-type section (relayed untouched).
pub struct ParseMessage<'a> {
    pub statement: &'a [u8],
    pub query: &'a [u8],
    pub param_types: &'a [u8],
}

pub fn parse_parse(mut body: &[u8]) -> Result<ParseMessage<'_>, Error> {
    let statement = take_cstr(&mut body)?;
    let query = take_cstr(&mut body)?;
    Ok(ParseMessage { statement, query, param_types: body })
}

pub fn encode_parse(statement: &[u8], query: &[u8], param_types: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(statement.len() + query.len() + param_types.len() + 2);
    out.extend_from_slice(statement);
    out.push(0);
    out.extend_from_slice(query);
    out.push(0);
    out.extend_from_slice(param_types);
    out
}

/// A parsed Bind ('B') message. Parameter format codes follow the protocol's
/// shorthand (empty = all text, one entry = applies to every parameter); the
/// result-format section is kept raw and relayed untouched.
pub struct BindMessage<'a> {
    pub portal: &'a [u8],
    pub statement: &'a [u8],
    pub param_formats: Vec<i16>,
    pub params: Vec<Option<&'a [u8]>>,
    pub result_formats: &'a [u8],
}

impl BindMessage<'_> {
    /// Resolves the format code (0 = text, 1 = binary) for one parameter.
    pub fn param_format(&self, index: usize) -> i16 {
        match self.param_formats.as_slice() {
            [] => 0,
            [only] => *only,
            formats => formats.get(index).copied().unwrap_or(0),
        }
    }
}

pub fn parse_bind(mut body: &[u8]) -> Result<BindMessage<'_>, Error> {
    let portal = take_cstr(&mut body)?;
    let statement = take_cstr(&mut body)?;
    let format_count = take_i16(&mut body)?;
    let mut param_formats = Vec::with_capacity(format_count.max(0) as usize);
    for _ in 0..format_count {
        param_formats.push(take_i16(&mut body)?);
    }
    let param_count = take_i16(&mut body)?;
    let mut params = Vec::with_capacity(param_count.max(0) as usize);
    for _ in 0..param_count {
        let len = i32::from_be_bytes(take(&mut body, 4)?.try_into().expect("4 bytes"));
        match len {
            -1 => params.push(None),
            0.. => params.push(Some(take(&mut body, len as usize)?)),
            _ => return Err(Error::MalformedBackend),
        }
    }
    Ok(BindMessage { portal, statement, param_formats, params, result_formats: body })
}

pub fn encode_bind(
    portal: &[u8],
    statement: &[u8],
    param_formats: &[i16],
    params: &[Option<std::borrow::Cow<'_, [u8]>>],
    result_formats: &[u8],
) -> Vec<u8> {
    let payload: usize = params.iter().map(|p| p.as_ref().map_or(0, |p| p.len())).sum();
    let mut out = Vec::with_capacity(
        portal.len()
            + statement.len()
            + 2
            + 4
            + param_formats.len() * 2
            + params.len() * 4
            + payload
            + result_formats.len(),
    );
    out.extend_from_slice(portal);
    out.push(0);
    out.extend_from_slice(statement);
    out.push(0);
    out.extend_from_slice(&(param_formats.len() as i16).to_be_bytes());
    for format in param_formats {
        out.extend_from_slice(&format.to_be_bytes());
    }
    out.extend_from_slice(&(params.len() as i16).to_be_bytes());
    for param in params {
        match param {
            None => out.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(p) => {
                out.extend_from_slice(&(p.len() as i32).to_be_bytes());
                out.extend_from_slice(p);
            }
        }
    }
    out.extend_from_slice(result_formats);
    out
}

/// Takes a NUL-terminated string, returning it without the terminator.
pub fn take_cstr<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let end = buf.iter().position(|&b| b == 0).ok_or(Error::MalformedBackend)?;
    let (head, rest) = buf.split_at(end);
    *buf = &rest[1..];
    Ok(head)
}

fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], Error> {
    let (head, rest) = buf.split_at_checked(n).ok_or(Error::MalformedBackend)?;
    *buf = rest;
    Ok(head)
}

fn take_i16(buf: &mut &[u8]) -> Result<i16, Error> {
    Ok(i16::from_be_bytes(take(buf, 2)?.try_into().expect("2 bytes")))
}

fn skip_cstr(buf: &mut &[u8]) -> Result<(), Error> {
    take_cstr(buf).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_startup_codes() {
        assert_eq!(startup_kind(SSL_REQUEST), Startup::Tls);
        assert_eq!(startup_kind(GSSENC_REQUEST), Startup::GssEnc);
        assert_eq!(startup_kind(CANCEL_REQUEST), Startup::Cancel);
        assert_eq!(startup_kind(PROTOCOL_V3), Startup::Protocol(PROTOCOL_V3));
    }

    #[test]
    fn startup_len_bounds() {
        assert_eq!(startup_body_len(8i32.to_be_bytes()).unwrap(), 4);
        assert!(startup_body_len(7i32.to_be_bytes()).is_err());
        assert!(startup_body_len(0i32.to_be_bytes()).is_err());
        assert!(startup_body_len((-1i32).to_be_bytes()).is_err());
        assert!(startup_body_len(((MAX_MESSAGE_LEN as i32) + 1).to_be_bytes()).is_err());
    }

    /// One RowDescription field with the given identity, text format.
    fn row_field(name: &[u8], table_oid: u32, attnum: i16) -> Vec<u8> {
        let mut out = name.to_vec();
        out.push(0);
        out.extend_from_slice(&table_oid.to_be_bytes());
        out.extend_from_slice(&attnum.to_be_bytes());
        out.extend_from_slice(&25u32.to_be_bytes()); // type oid (text)
        out.extend_from_slice(&(-1i16).to_be_bytes()); // type len
        out.extend_from_slice(&(-1i32).to_be_bytes()); // type mod
        out.extend_from_slice(&0i16.to_be_bytes()); // format
        out
    }

    #[test]
    fn parses_row_description() {
        let mut body = 2i16.to_be_bytes().to_vec();
        body.extend_from_slice(&row_field(b"id", 1234, 1));
        body.extend_from_slice(&row_field(b"email", 1234, 2));
        assert_eq!(
            parse_row_description(&body).unwrap(),
            vec![RowField { table_oid: 1234, attnum: 1 }, RowField { table_oid: 1234, attnum: 2 }]
        );

        assert!(parse_row_description(&body[..body.len() - 1]).is_err());
        body.push(0);
        assert!(parse_row_description(&body).is_err());
    }

    #[test]
    fn parse_message_roundtrips() {
        let body = encode_parse(b"stmt", b"SELECT $1", &2i16.to_be_bytes());
        let parsed = parse_parse(&body).unwrap();
        assert_eq!(parsed.statement, b"stmt");
        assert_eq!(parsed.query, b"SELECT $1");
        assert_eq!(parsed.param_types, 2i16.to_be_bytes());

        assert!(parse_parse(b"no terminator").is_err());
    }

    #[test]
    fn bind_message_roundtrips() {
        use std::borrow::Cow;
        let result_formats = {
            let mut r = 1i16.to_be_bytes().to_vec();
            r.extend_from_slice(&1i16.to_be_bytes());
            r
        };
        let body = encode_bind(
            b"portal",
            b"stmt",
            &[0, 1],
            &[Some(Cow::Borrowed(b"abc".as_slice())), None],
            &result_formats,
        );
        let parsed = parse_bind(&body).unwrap();
        assert_eq!(parsed.portal, b"portal");
        assert_eq!(parsed.statement, b"stmt");
        assert_eq!(parsed.param_formats, vec![0, 1]);
        assert_eq!(parsed.params, vec![Some(b"abc".as_slice()), None]);
        assert_eq!(parsed.result_formats, result_formats);

        assert_eq!(parsed.param_format(0), 0);
        assert_eq!(parsed.param_format(1), 1);
        assert_eq!(
            BindMessage { param_formats: vec![], ..parse_bind(&body).unwrap() }.param_format(1),
            0
        );
        assert_eq!(
            BindMessage { param_formats: vec![1], ..parse_bind(&body).unwrap() }.param_format(1),
            1
        );
    }

    #[test]
    fn data_row_roundtrips() {
        use std::borrow::Cow;
        let values =
            [Some(Cow::Borrowed(b"abc".as_slice())), None, Some(Cow::Borrowed(b"".as_slice()))];
        let body = encode_data_row(&values);
        assert_eq!(
            parse_data_row(&body).unwrap(),
            vec![Some(b"abc".as_slice()), None, Some(b"".as_slice())]
        );

        assert!(parse_data_row(&body[..body.len() - 1]).is_err());
    }

    #[test]
    fn frame_len_bounds() {
        let mut header = [0u8; FRAME_HEADER_LEN];
        header[0] = b'Q';
        header[1..].copy_from_slice(&9i32.to_be_bytes());
        assert_eq!(frame_body_len(&header).unwrap(), (b'Q', 5));

        header[1..].copy_from_slice(&4i32.to_be_bytes());
        assert_eq!(frame_body_len(&header).unwrap(), (b'Q', 0));

        header[1..].copy_from_slice(&3i32.to_be_bytes());
        assert!(frame_body_len(&header).is_err());

        header[1..].copy_from_slice(&(-5i32).to_be_bytes());
        assert!(frame_body_len(&header).is_err());
    }
}
