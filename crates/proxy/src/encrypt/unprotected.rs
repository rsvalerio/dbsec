//! The catalogue of places the proxy cannot protect, and how it says so.
//!
//! Every variant here is a documented hole in the "a protected column is never
//! at rest in plaintext" invariant — a statement shape the rewrite cannot
//! cover, or a predicate no blind-index match can express. They are enumerated
//! in one enum rather than inlined at their call sites so the set can be read,
//! counted and kept in step with the README, and so each one has exactly one
//! warning wording and one refusal wording.
//!
//! The two wordings are not interchangeable. The warning is what `warn` mode
//! writes to the log and what operators build alerting on, so its prefix is
//! kept stable; the refusal is what the client is told under `reject`, and it
//! names the remedy. Neither may carry a plaintext value — the column and the
//! *shape* of the expression are what identify the site.

use dbsec_pgwire as pgwire;
use sqlparser::ast::ObjectName;
use sqlparser::parser::ParserError;

/// Every place a write to a protected column is not rewritten, or a predicate
/// over a searchable column is not turned into an index match. Each one is a
/// documented hole in the "never at rest in plaintext" invariant, which is
/// why they are enumerated here rather than inlined at the call sites.
pub(super) enum Unprotected<'a> {
    /// The Query body is not valid UTF-8, so it cannot be parsed at all.
    NonUtf8,
    /// sqlparser could not parse the SQL.
    Unparseable(&'a ParserError),
    /// `INSERT` without a column list: values cannot be matched to columns.
    NoColumnList(&'a ObjectName),
    /// `INSERT ... SELECT`: the values are rows, not literals.
    InsertFromSelect(&'a ObjectName),
    /// `COPY`, whose payload is a `CopyData` stream the proxy does not parse.
    ///
    /// The `to` direction fires for anything the read path protects, the
    /// `from` direction only for what the write path would have sealed — see
    /// [`WriteCatalog::protects_reads`](super::catalog::WriteCatalog::protects_reads)
    /// for why a mask-only table belongs in the first set and not the second.
    Copy { table: &'a ObjectName, to: bool },
    /// `COPY (query) TO STDOUT` over a protected table. Kept apart from
    /// [`Self::Copy`] because the remedy differs — there is no table to bulk
    /// load differently, only a query to run as an ordinary `SELECT` so its
    /// rows come back as `DataRow` frames the read path can decrypt and mask.
    CopyQuery { table: String },
    /// A statement shape that writes a protected table but is not rewritten.
    Unsupported { table: &'a ObjectName, shape: &'static str },
    /// An ordinary `'…'` literal carrying a backslash, in a session that
    /// turned `standard_conforming_strings` off — so the server and the
    /// proxy's parser no longer read it as the same bytes.
    AmbiguousLiteral { column: &'a str },
    /// A non-literal expression assigned to a protected column.
    UnsupportedValue { column: &'a str, shape: &'static str },
    /// A protected column projected through an expression rather than
    /// selected directly. The result has no table OID, so the read path
    /// cannot recognise it and relays the stored form — or, for a mask-only
    /// column, the plaintext the mask exists to hide.
    ComputedColumn { column: String, shape: &'static str },
    /// A statement writing a row-bound table that does not say which row it
    /// writes, so the value could not be sealed against one.
    ///
    /// Its own variant rather than [`Self::UnsupportedValue`] because the
    /// remedy is different in kind: that one is a value to express
    /// differently, this one is a statement that must carry the table's row
    /// key — often meaning the application has to stop relying on a
    /// server-generated one.
    RowKeyMissing { table: String, column: String, shape: &'static str },
    /// An assignment list on a row-bound table that writes the row key column
    /// itself — `UPDATE users SET ssn = 'x', id = 99 WHERE id = 7`, or the
    /// same shape in a conflict action.
    ///
    /// Kept apart from [`Self::RowKeyMissing`] because the statement *does*
    /// name a row: it names the row the values are being moved out of. Sealing
    /// against that key stores bytes the row they land in can never open, so
    /// the remedy is to move the row and write the protected column in
    /// separate statements, not to supply a key.
    RowKeyReassigned { table: String, column: String },
    /// A predicate over a searchable column that no index match can express.
    Predicate { column: String, shape: &'static str },
    /// An unqualified name matching a protected column in more than one
    /// relation in scope. Nothing was rewritten, because choosing one of them
    /// would compare against the wrong table's blind index — and an
    /// unrewritten predicate over a protected column matches no row.
    AmbiguousColumn { column: String, shape: &'static str },
    /// A predicate over a protected column that has no equality index at all,
    /// so no rewrite could express it. Kept apart from [`Self::Predicate`]
    /// because the remedy differs: that one is a query to rewrite, this one is
    /// a column to reconfigure.
    UnindexedPredicate { column: String, shape: &'static str },
    /// `search_path` moved off the schema the catalog resolves against.
    SearchPathChanged,
    /// `standard_conforming_strings` was turned off. Sealed values are emitted
    /// in a form that does not depend on it
    /// ([`bytea_literal`](super::seal::bytea_literal)), but the client's own
    /// literals are now read one way by PostgreSQL and another by the proxy's
    /// parser — reported here once, and again per literal that the difference
    /// actually reaches ([`Self::AmbiguousLiteral`]).
    EscapeStringsChanged,
    /// An unqualified name that may be a protected table, in a session whose
    /// `search_path` no longer says which schema it resolves to.
    SearchPath(&'a ObjectName),
}

impl Unprotected<'_> {
    /// Emits the site's warning. The wording of the six original passthrough
    /// sites is kept prefix-compatible so log-based alerting keeps matching;
    /// only the fields that carried plaintext (the bound expression, the
    /// parser's message) are gone, replaced by the shape and the parser error
    /// kind. [`Self::Copy`] gained "or masked" once it started firing for
    /// mask-only tables, which carry no encryption to be bypassed.
    pub(super) fn warn(&self) {
        match self {
            Self::NonUtf8 => {
                tracing::warn!("query is not valid UTF-8; passing through unencrypted");
            }
            Self::Unparseable(error) => {
                tracing::warn!(
                    error_kind = parser_error_kind(error),
                    "unparseable SQL; passing through unencrypted"
                );
            }
            Self::NoColumnList(table) => tracing::warn!(
                table = %table,
                "INSERT without a column list on a protected table; passing through unencrypted"
            ),
            Self::InsertFromSelect(table) => tracing::warn!(
                table = %table,
                "INSERT ... SELECT into a protected table; passing through unencrypted"
            ),
            Self::Copy { table, to } => tracing::warn!(
                table = %table,
                direction = if *to { "to" } else { "from" },
                "COPY on a protected table is not encrypted or masked by the proxy"
            ),
            Self::CopyQuery { table } => tracing::warn!(
                table,
                direction = "to",
                "COPY of a query over a protected table streams its rows as CopyData, which the \
                 read path cannot decrypt or mask"
            ),
            Self::Unsupported { table, shape } => tracing::warn!(
                table = %table,
                shape,
                "statement writes a protected table but is not rewritten; passing through unencrypted"
            ),
            Self::AmbiguousLiteral { column } => tracing::warn!(
                column,
                "string literal contains a backslash and this session turned \
                 standard_conforming_strings off, so the proxy cannot read it the way the \
                 server will; passing through unencrypted"
            ),
            Self::UnsupportedValue { column, shape } => tracing::warn!(
                column,
                shape,
                "unsupported expression for a protected column; passing through unencrypted"
            ),
            Self::ComputedColumn { column, shape } => tracing::warn!(
                column,
                shape,
                "protected column projected through an expression; the result has no table OID, \
                 so the read path cannot decrypt or mask it and will relay the stored value"
            ),
            Self::RowKeyMissing { table, column, shape } => tracing::warn!(
                table = %table,
                row_key = %column,
                shape,
                "row-bound table written without its row key; the value is sealed against its \
                 column only. It still decrypts — what is lost is relocation detection: it can \
                 be copied into another row of this column undetected until it is re-encrypted. \
                 Set strict_row_binding on this [[table]] to have such a value refused on read \
                 instead of opening"
            ),
            Self::RowKeyReassigned { table, column } => tracing::warn!(
                table = %table,
                row_key = %column,
                "assignment list on a row-bound table writes its row key; a value sealed here \
                 would be bound to the row the statement moves it out of and will not open"
            ),
            Self::Predicate { column, shape } => tracing::warn!(
                column,
                shape,
                "unsupported predicate for a searchable column; it will match no rows"
            ),
            Self::AmbiguousColumn { column, shape } => tracing::warn!(
                column,
                shape,
                "unqualified column matches a protected column in more than one relation in \
                 scope, so the predicate cannot be rewritten and will match no rows; qualify \
                 it with its table or alias"
            ),
            Self::UnindexedPredicate { column, shape } => tracing::warn!(
                column,
                shape,
                "predicate over a protected column with no equality index; it will match no rows \
                 because the stored form is not the plaintext. Set searchable = true on this \
                 column to make equality searchable"
            ),
            Self::SearchPathChanged => tracing::warn!(
                "session changed search_path; unqualified names no longer resolve to the \
                 configured schema"
            ),
            Self::EscapeStringsChanged => tracing::warn!(
                "session turned standard_conforming_strings off; a backslash in a string \
                 literal no longer means to PostgreSQL what the proxy reads it as"
            ),
            Self::SearchPath(table) => tracing::warn!(
                table = %table,
                "unqualified name may be a protected table under this session's search_path; \
                 passing through unencrypted"
            ),
        }
    }

    /// The ErrorResponse text for the refusal. Identifiers and shapes only —
    /// this goes to the client, but it also lands in its logs.
    pub(super) fn message(&self) -> String {
        let detail = match self {
            Self::NonUtf8 => {
                "the query is not valid UTF-8, so protected columns cannot be found in it"
                    .to_owned()
            }
            Self::Unparseable(error) => format!(
                "the SQL could not be parsed ({}), so protected columns cannot be found in it",
                parser_error_kind(error)
            ),
            Self::NoColumnList(table) => {
                format!("INSERT into protected table {table} needs an explicit column list")
            }
            Self::InsertFromSelect(table) => {
                format!("INSERT ... SELECT into protected table {table} cannot be encrypted")
            }
            Self::Copy { table, to } => format!(
                "COPY {} protected table {table} bypasses the proxy's encryption and masking",
                if *to { "from" } else { "into" }
            ),
            Self::CopyQuery { table } => format!(
                "COPY of a query reading protected table {table} returns its rows as CopyData, \
                 which cannot be decrypted or masked; run the query as an ordinary SELECT instead"
            ),
            Self::Unsupported { table, shape } => {
                format!("{shape} writing protected table {table} cannot be encrypted")
            }
            Self::AmbiguousLiteral { column } => format!(
                "a value for protected column {column} contains a backslash and this session \
                 turned standard_conforming_strings off, so the proxy cannot read it the way \
                 the server will"
            ),
            Self::UnsupportedValue { column, shape } => format!(
                "protected column {column} was assigned a {shape}, which cannot be encrypted"
            ),
            Self::ComputedColumn { column, shape } => format!(
                "protected column {column} was projected through a {shape}; the result carries no \
                 table identity, so it cannot be decrypted or masked and would be returned in its \
                 stored form; select the column directly instead"
            ),
            Self::RowKeyMissing { table, column, shape } => format!(
                "{table} binds its encrypted values to the row key {column}, but this is a \
                 {shape}; the statement must supply {column} as a literal or a parameter"
            ),
            Self::RowKeyReassigned { table, column } => format!(
                "{table} binds its encrypted values to the row key {column}, and this statement \
                 assigns {column} itself, so the value would be sealed against a row it does not \
                 land in; change {column} in a statement that writes no protected column of \
                 {table}"
            ),
            Self::Predicate { column, shape } => format!(
                "searchable column {column} was used in a {shape}, which cannot be matched \
                 against its blind index"
            ),
            Self::AmbiguousColumn { column, shape } => format!(
                "column {column} in a {shape} matches a protected column in more than one \
                 relation in scope, so it cannot be resolved to one and the comparison would \
                 match no rows; qualify it with its table or alias"
            ),
            Self::UnindexedPredicate { column, shape } => format!(
                "protected column {column} was used in a {shape}, but it has no equality index, \
                 so the comparison would match no rows; set searchable = true on this column to \
                 make equality searchable"
            ),
            Self::SearchPathChanged => {
                "changing search_path leaves unqualified names resolving to an unknown schema"
                    .to_owned()
            }
            Self::EscapeStringsChanged => {
                "turning standard_conforming_strings off changes what a backslash in a string \
                 literal means, so a value bound to a protected column can no longer be read \
                 the way the server would read it"
                    .to_owned()
            }
            Self::SearchPath(table) => format!(
                "{table} is unqualified and this session changed search_path, so it cannot be \
                 resolved to a protected table"
            ),
        };
        format!("dbsec refused this statement: {detail} (on_unprotected = \"reject\")")
    }
}

/// The parser error's variant. Never its message: sqlparser embeds the
/// offending token in the text, which for a literal is the plaintext itself.
///
/// `pub(super)` with no caller outside this file on purpose: the module docs
/// in `encrypt/mod.rs` name it as the thing that makes the audited `error_kind`
/// field safe to log, and a link the reader can follow is worth more than one
/// less name in the sibling scope.
pub(super) fn parser_error_kind(error: &ParserError) -> &'static str {
    match error {
        ParserError::TokenizerError(_) => "tokenizer",
        ParserError::ParserError(_) => "parser",
        ParserError::RecursionLimitExceeded => "recursion limit",
    }
}

/// SQLSTATE 42501 (insufficient_privilege): the statement is well-formed, the
/// proxy's policy is what refuses it. Clients treat it as fatal for the
/// statement and do not retry, which is the intent.
const REFUSED_SQLSTATE: &str = "42501";

/// How much of a refusal message goes on the wire. The message embeds SQL
/// identifiers, which are as long as the client cares to make them.
const MAX_ERROR_MESSAGE: usize = 512;

/// A PostgreSQL ErrorResponse ('E') frame. Recoverable at the statement
/// level: the session stays open and the client can carry on.
///
/// Shared with the read path ([`crate::rows`]), which refuses a result set it
/// cannot safely relay with the same frame and the same SQLSTATE: both are the
/// proxy's policy declining one statement, and a client that knows what 42501
/// means from a refused write should not have to learn a second code for a
/// refused read.
pub(crate) fn error_response(message: &str) -> Vec<u8> {
    let mut end = MAX_ERROR_MESSAGE.min(message.len());
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let truncated = &message[..end];
    let mut body = Vec::with_capacity(truncated.len() + 32);
    for (field, value) in
        [(b'S', "ERROR"), (b'V', "ERROR"), (b'C', REFUSED_SQLSTATE), (b'M', truncated)]
    {
        body.push(field);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    frame(b'E', &body)
}

/// Wraps a message body in its `type | length` header.
pub(super) fn frame(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let length = i32::try_from(pgwire::FRAME_HEADER_LEN - 1 + body.len()).unwrap_or(i32::MAX);
    let mut out = Vec::with_capacity(pgwire::FRAME_HEADER_LEN + body.len());
    out.push(msg_type);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::lexer::parse_sql;

    /// The parser's own message embeds the token it choked on — which for a
    /// literal is the plaintext — so only the variant is logged.
    #[test]
    fn parser_errors_are_reduced_to_their_kind() {
        let error = parse_sql("UPDATE users SET email 'a@b.io'").expect_err("does not parse");
        assert!(format!("{error}").contains("a@b.io"), "precondition: the message leaks");
        let site = Unprotected::Unparseable(&error);
        assert!(!site.message().contains("a@b.io"), "{}", site.message());
        assert_eq!(parser_error_kind(&error), "parser");
    }

    #[test]
    fn error_response_is_a_well_formed_frame() {
        let bytes = error_response("nope");
        assert_eq!(bytes[0], b'E');
        let length = i32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
        assert_eq!(length, bytes.len() - 1);
        assert_eq!(*bytes.last().unwrap(), 0, "field list is terminated");
        let body = String::from_utf8_lossy(&bytes[5..]);
        assert!(body.contains("ERROR") && body.contains(REFUSED_SQLSTATE) && body.contains("nope"));
        assert_eq!(message_field(&bytes), "nope");
    }

    /// The 'M' field as the client reads it: the bytes between the field
    /// marker and its terminator, decoded strictly — a truncation that split a
    /// character would fail here rather than be papered over.
    fn message_field(bytes: &[u8]) -> String {
        let field = bytes[pgwire::FRAME_HEADER_LEN..]
            .split(|byte| *byte == 0)
            .find(|field| field.first() == Some(&b'M'))
            .expect("an M field");
        String::from_utf8(field[1..].to_vec()).expect("the message is valid UTF-8")
    }

    /// The cap and the boundary walk are both security properties, so both are
    /// pinned. The cap bounds attacker-influenced text on the wire — the
    /// message embeds client-chosen identifiers — and the walk is what stops a
    /// multi-byte identifier truncated mid-character from panicking on the
    /// slice, which a client could trigger at will.
    #[test]
    fn a_long_message_is_truncated_at_the_cap_and_on_a_char_boundary() {
        // Pinned, not merely bounded: raising the cap puts more of a
        // client-chosen identifier on the wire, so the number is part of the
        // contract rather than an implementation detail.
        assert_eq!(MAX_ERROR_MESSAGE, 512);
        let long = message_field(&error_response(&"x".repeat(4096)));
        assert_eq!(long, "x".repeat(MAX_ERROR_MESSAGE));

        // A message whose byte `MAX_ERROR_MESSAGE` falls inside a multi-byte
        // character: an ASCII prefix one byte short of the cap, then a
        // three-byte character straddling it. Slicing at the cap would panic,
        // so the walk has to step back to the boundary before it.
        let straddling = format!("{}\u{20ac}{}", "x".repeat(MAX_ERROR_MESSAGE - 1), "y".repeat(8));
        assert_eq!(message_field(&error_response(&straddling)), "x".repeat(MAX_ERROR_MESSAGE - 1));
    }
}
