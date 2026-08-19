//! Folding a SQL identifier the way PostgreSQL folds it.
//!
//! A protected column is named twice: once in whatever declares it — the
//! proxy's `[[column]]` entries, or a policy an application builds in code —
//! and again in the SQL that touches it. The two names have to compare equal,
//! and PostgreSQL's rules for that are not Rust's.
//!
//! This lives in the library rather than beside either caller because the
//! folded name is what ends up inside [`crate::envelope::CellContext`], and so
//! inside the associated data of every envelope written for that column. Two
//! callers that fold differently do not merely fail to match a name; they seal
//! against different contexts, and the values one writes never open through the
//! other.

use std::borrow::Cow;

/// PostgreSQL's `NAMEDATALEN - 1`: the most bytes of an identifier the server
/// keeps. Anything longer is truncated on the way into the catalog, and every
/// later reference to the long name resolves to the truncated one.
pub const MAX_IDENTIFIER_BYTES: usize = 63;

/// Folds a SQL identifier the way PostgreSQL does, so that a name written in a
/// query and the same name written in a column policy compare equal.
///
/// Both halves of this are places where Rust's own string handling would give
/// a different answer than the server, and a mismatch here is not a parse
/// error: it makes a protected column look unprotected, and the write path
/// relays the plaintext.
///
/// - An *unquoted* identifier is downcased **ASCII-only**. `str::to_lowercase`
///   applies full Unicode case folding — `Ä` to `ä`, the Kelvin sign `K`
///   (U+212A) to `k` — while PostgreSQL under a UTF-8 server encoding leaves
///   every multibyte character exactly as written. A quoted identifier is not
///   folded at all.
/// - Every identifier, quoted or not, is clipped to
///   [`MAX_IDENTIFIER_BYTES`] on a character boundary (the server's
///   `pg_mbcliplen`).
pub fn fold_identifier(value: &str, quoted: bool) -> Cow<'_, str> {
    let clipped = truncate_identifier(value);
    if quoted || !clipped.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Cow::Borrowed(clipped);
    }
    Cow::Owned(clipped.to_ascii_lowercase())
}

/// Clips an identifier to the bytes PostgreSQL keeps, never splitting a
/// character.
fn truncate_identifier(value: &str) -> &str {
    if value.len() <= MAX_IDENTIFIER_BYTES {
        return value;
    }
    let mut end = MAX_IDENTIFIER_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each assertion is a case where `str::to_lowercase` or a byte-wise
    /// truncation would disagree with the server.
    #[test]
    fn identifiers_fold_the_way_postgresql_folds_them() {
        assert_eq!(fold_identifier("EMail", false), "email");
        // Multibyte characters are left exactly as written: PostgreSQL under a
        // UTF-8 encoding downcases ASCII only.
        assert_eq!(fold_identifier("ÄMAIL", false), "Ämail");
        assert_eq!(fold_identifier("\u{212a}elvin", false), "\u{212a}elvin");
        // A quoted identifier keeps its case.
        assert_eq!(fold_identifier("EMail", true), "EMail");

        // Clipping happens on a character boundary, so a name of multibyte
        // characters clips to fewer characters than the byte limit.
        let long = "é".repeat(MAX_IDENTIFIER_BYTES);
        let folded = fold_identifier(&long, false);
        assert_eq!(folded, "é".repeat(MAX_IDENTIFIER_BYTES / 2));
        assert!(folded.len() <= MAX_IDENTIFIER_BYTES);
    }

    /// A name that is already folded borrows rather than allocating — the
    /// write path calls this on every identifier it reads out of SQL.
    #[test]
    fn an_already_folded_name_is_borrowed() {
        assert!(matches!(fold_identifier("email", false), Cow::Borrowed(_)));
        assert!(matches!(fold_identifier("EMail", false), Cow::Owned(_)));
    }
}
