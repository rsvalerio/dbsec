//! Splitting one client SQL text into its statements, without a parser.
//!
//! sqlparser gives the statements but not their source spans, and the write
//! path needs the spans: a statement it did not rewrite must reach the server
//! as the client wrote it, comments and all. So this is a second, much smaller
//! lexer over the same text, and its only job is to find the `;` that separate
//! statements while stepping over the places one can hide — quoted strings,
//! dollar-quoted bodies, comments.
//!
//! It is deliberately conservative: when it cannot map ranges to statements
//! one-to-one the caller re-renders everything instead, which is correct but
//! loses the original text.

use std::ops::Range;

use sqlparser::ast::Statement;

use super::parse_sql;
use crate::Error;

/// Rebuilds the SQL text, re-rendering only the statements that changed and
/// keeping everything else — the untouched statements, the separators, the
/// comments around them — exactly as the client wrote it.
pub(super) fn reassemble(
    sql: &str,
    statements: &[Statement],
    changed: &[bool],
) -> Result<String, Error> {
    let Some(ranges) = statement_ranges(sql).filter(|ranges| ranges.len() == statements.len())
    else {
        // The source text could not be lined up with the parsed statements,
        // so there is no original text to preserve. Every statement is
        // rendered, and every rendering is validated below.
        tracing::warn!(
            statements = statements.len(),
            "could not map statements back to their source text; re-rendering all of them"
        );
        let rendered: Result<Vec<String>, Error> =
            statements.iter().map(render_validated).collect();
        return Ok(rendered?.join("; "));
    };
    let mut out = String::with_capacity(sql.len());
    let mut cursor = 0;
    for ((range, statement), changed) in ranges.iter().zip(statements).zip(changed) {
        out.push_str(&sql[cursor..range.start]);
        if *changed {
            out.push_str(&render_validated(statement)?);
        } else {
            out.push_str(&sql[range.clone()]);
        }
        cursor = range.end;
    }
    out.push_str(&sql[cursor..]);
    Ok(out)
}

/// Renders a rewritten statement and checks that it means what the AST says:
/// re-parse it and compare. sqlparser's `Display` is not contractually a
/// round-trip, and this is the one path where the proxy hands the server SQL
/// the client never wrote — a divergence has to fail the session, because the
/// alternative is executing a valid statement with different semantics.
pub(super) fn render_validated(statement: &Statement) -> Result<String, Error> {
    let rendered = statement.to_string();
    match parse_sql(&rendered) {
        Ok(reparsed) if reparsed.len() == 1 && reparsed[0] == *statement => Ok(rendered),
        _ => Err(Error::RewriteDiverged),
    }
}

/// The byte ranges of the top-level statements in `sql`, trimmed of
/// surrounding whitespace. `None` when the text cannot be split with
/// confidence — an unterminated literal, identifier, dollar-quoted body or
/// block comment — in which case the caller does not try to preserve it.
fn statement_ranges(sql: &str) -> Option<Vec<Range<usize>>> {
    let bytes = sql.as_bytes();
    let mut ranges: Vec<Range<usize>> = Vec::new();
    let mut start = 0;
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'\'' | b'"' => at = skip_quoted(bytes, at)?,
            b'$' => at = skip_dollar_quoted(bytes, at)?,
            b'-' if bytes.get(at + 1) == Some(&b'-') => {
                at = bytes[at..].iter().position(|&b| b == b'\n').map_or(bytes.len(), |n| at + n);
            }
            b'/' if bytes.get(at + 1) == Some(&b'*') => at = skip_block_comment(bytes, at)?,
            b';' => {
                push_statement(&mut ranges, sql, start..at);
                at += 1;
                start = at;
            }
            _ => at += 1,
        }
    }
    push_statement(&mut ranges, sql, start..bytes.len());
    Some(ranges)
}

fn push_statement(ranges: &mut Vec<Range<usize>>, sql: &str, range: Range<usize>) {
    let text = &sql[range.clone()];
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return;
    }
    let start = range.start + (text.len() - text.trim_start().len());
    ranges.push(start..start + trimmed.len());
}

/// Skips a `'...'` literal or a `"..."` identifier, both of which escape the
/// closing character by doubling it. `E'...'` also escapes with backslashes.
fn skip_quoted(bytes: &[u8], start: usize) -> Option<usize> {
    let quote = bytes[start];
    let backslash_escapes = quote == b'\''
        && start > 0
        && matches!(bytes[start - 1], b'e' | b'E')
        && (start == 1 || !is_ident_byte(bytes[start - 2]));
    let mut at = start + 1;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' if backslash_escapes => at += 2,
            b if b == quote => {
                if bytes.get(at + 1) == Some(&quote) {
                    at += 2;
                } else {
                    return Some(at + 1);
                }
            }
            _ => at += 1,
        }
    }
    None
}

/// Skips a `$tag$ ... $tag$` body. A `$` that does not open one — a `$1`
/// placeholder, say — just advances one byte.
///
/// Misjudging a tag is not a harmless miss. A rejected candidate advances a
/// single byte, which walks the scan *into* the body, where quoted text is
/// read as SQL: a `;` that is really literal data splits a statement, and a
/// closing `$tag$` is mistaken for an opening one. Either way the ranges stop
/// corresponding to the parsed statements, and the `ranges.len() ==
/// statements.len()` guard in [`reassemble`] is a count check, not an
/// alignment check.
fn skip_dollar_quoted(bytes: &[u8], start: usize) -> Option<usize> {
    let tag_end = bytes[start + 1..]
        .iter()
        .position(|&b| b == b'$')
        .map(|n| start + 1 + n)
        .filter(|end| is_dollar_tag(&bytes[start + 1..*end]));
    let Some(tag_end) = tag_end else { return Some(start + 1) };
    let tag = &bytes[start..=tag_end];
    let mut at = tag_end + 1;
    while at + tag.len() <= bytes.len() {
        if &bytes[at..at + tag.len()] == tag {
            return Some(at + tag.len());
        }
        at += 1;
    }
    None
}

/// PostgreSQL's dollar-quote tag rule: empty (`$$ ... $$`), or an unquoted
/// identifier — a leading byte that is not a digit, then identifier bytes.
/// Digits are legal after the first character, so `$tag1$` opens a body; the
/// previous rule rejected a digit anywhere and mis-lexed it.
///
/// Non-ASCII bytes count as identifier bytes here because PostgreSQL
/// identifiers admit non-ASCII letters. The bias is deliberate: accepting a
/// tag PostgreSQL would not costs only the caller's text-preservation fast
/// path (the ranges stop matching the statement count and everything is
/// re-rendered), while rejecting a real one corrupts the ranges themselves.
fn is_dollar_tag(tag: &[u8]) -> bool {
    match tag.first() {
        None => true,
        Some(&first) if first.is_ascii_digit() => false,
        _ => tag.iter().all(|&b| is_ident_byte(b) || b >= 0x80),
    }
}

/// Skips a `/* ... */` comment, which PostgreSQL allows to nest.
fn skip_block_comment(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut at = start;
    while at + 1 < bytes.len() {
        match (bytes[at], bytes[at + 1]) {
            (b'/', b'*') => {
                depth += 1;
                at += 2;
            }
            (b'*', b'/') => {
                depth -= 1;
                at += 2;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => at += 1,
        }
    }
    None
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::TestCaseError;
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    #[test]
    fn statement_ranges_respect_quoting_and_comments() {
        let sql = "SELECT ';', \";\", $q$;$q$, E'\\'; ' /* ; */ -- ;\n; SELECT 2";
        let ranges = statement_ranges(sql).expect("splits");
        assert_eq!(
            ranges.len(),
            2,
            "{:?}",
            ranges.iter().map(|r| &sql[r.clone()]).collect::<Vec<_>>()
        );
        assert_eq!(&sql[ranges[1].clone()], "SELECT 2");

        // Unterminated constructs are not guessed at.
        assert!(statement_ranges("SELECT 'oops").is_none());
        assert!(statement_ranges("SELECT $q$oops").is_none());
        assert!(statement_ranges("SELECT 1 /* oops").is_none());
    }

    /// A dollar-quote tag follows PostgreSQL's identifier rule, so digits are
    /// legal after the first character. Rejecting them walked the scan into
    /// the quoted body, where a `;` in literal data split the statement and a
    /// closing tag was read as an opening one.
    #[test]
    fn dollar_quote_tags_may_contain_digits() {
        // A `;` inside the body is data, not a separator.
        let sql = "SELECT $tag1$a;b$tag1$";
        let ranges = statement_ranges(sql).expect("splits");
        assert_eq!(ranges.len(), 1, "the ; is inside the quoted body: {ranges:?}");
        assert_eq!(&sql[ranges[0].clone()], sql);

        // Tags that are digits-only, or start with one, are not tags: `$1` is
        // a placeholder and must not swallow the text up to the next `$`.
        let sql = "SELECT a FROM t WHERE x = $1 AND y = $2; SELECT 2";
        let ranges = statement_ranges(sql).expect("splits");
        assert_eq!(ranges.len(), 2, "placeholders are not dollar quotes: {ranges:?}");
        assert_eq!(&sql[ranges[1].clone()], "SELECT 2");

        // Underscore-led and empty tags keep working.
        for sql in ["SELECT $_x1$;$_x1$", "SELECT $$;$$"] {
            assert_eq!(statement_ranges(sql).expect("splits").len(), 1, "{sql}");
        }

        // Still no guessing at an unterminated body.
        assert!(statement_ranges("SELECT $tag1$oops").is_none());
    }

    /// Statement fragments chosen for their lexical hazards: every one holds a
    /// `;` (or a `$`) somewhere the scanner must *not* treat as a separator.
    fn statement_fragment() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "SELECT 1",
            "SELECT ';'",
            "SELECT ''';'''",
            "SELECT \";\" FROM t",
            "SELECT $$;$$",
            "SELECT $tag$;$tag$",
            "SELECT $tag1$;$tag1$",
            "SELECT $_9$;$_9$",
            "SELECT E'\\';'",
            "SELECT 1 /* ; */",
            "SELECT 1 /* /* ; */ */",
            "SELECT a FROM t WHERE x = $1",
            "INSERT INTO users (email) VALUES ('a;b')",
            "UPDATE users SET email = $tag2$x;y$tag2$",
        ])
        .prop_map(str::to_owned)
    }

    proptest! {
        /// `statement_ranges` is a second, hand-written SQL lexer over
        /// client-controlled text, and it is the one component whose
        /// disagreement with sqlparser `render_validated` cannot catch: when
        /// the ranges are wrong but their *count* happens to match,
        /// `reassemble` splices rendered SQL at the wrong offsets and nothing
        /// re-parses the assembled result.
        ///
        /// The invariant: whenever the ranges line up with the parsed
        /// statements, each range's text must parse to exactly the statement
        /// sqlparser found at that position.
        #[test]
        fn statement_ranges_align_with_the_parsed_statements(
            fragments in proptest::collection::vec(statement_fragment(), 1..4),
            separator in prop::sample::select(vec!["; ", ";", " ; ", ";\n", "; -- c\n"]),
        ) {
            let sql = fragments.join(separator);
            let Ok(parsed) = parse_sql(&sql) else { return Ok(()) };
            let Some(ranges) = statement_ranges(&sql) else { return Ok(()) };
            // Asserted, not assumed. `reassemble` only checks that the two
            // counts agree, so a wrong split that happens to keep the count is
            // exactly the case that reaches the server mis-spliced — assuming
            // the counts match here would skip the bugs worth finding.
            prop_assert_eq!(
                ranges.len(), parsed.len(),
                "{:?} split into {:?}",
                sql, ranges.iter().map(|r| &sql[r.clone()]).collect::<Vec<_>>()
            );

            for (range, statement) in ranges.iter().zip(&parsed) {
                let text = &sql[range.clone()];
                let reparsed = parse_sql(text).map_err(|e| {
                    TestCaseError::fail(format!("range {text:?} does not parse: {e}"))
                })?;
                prop_assert_eq!(
                    reparsed.len(), 1,
                    "range {:?} holds {} statements, not one", text, reparsed.len()
                );
                prop_assert_eq!(
                    &reparsed[0], statement,
                    "range {:?} is not the statement at its position", text
                );
            }
        }
    }

    /// A rendered statement that does not re-parse to the same AST never
    /// reaches the server.
    #[test]
    fn rendered_statements_are_validated() {
        let statement =
            &Parser::parse_sql(&PostgreSqlDialect {}, "SELECT 1 FROM t").unwrap().pop().unwrap();
        assert_eq!(render_validated(statement).unwrap(), "SELECT 1 FROM t");
    }
}
