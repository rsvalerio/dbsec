//! Watching the session settings the rewrite's assumptions depend on.
//!
//! Two settings decide whether the proxy and the server still read a statement
//! the same way: `search_path`, which says what an unqualified table name
//! resolves to, and `standard_conforming_strings`, which says what a backslash
//! in a literal means. A session that moves either has diverged from what the
//! configuration was written against.
//!
//! This reads the **token stream** rather than the AST, for two reasons:
//! `SET SCHEMA` is not something sqlparser 0.53 can parse at all, and the
//! moves have to be attributed to individual statements of a batch — a `SET`
//! late in a batch must not retroactively unseal the writes in front of it.

use sqlparser::tokenizer::{Token, TokenWithSpan};

/// A session setting the rewrite's assumptions depend on, moved off the value
/// those assumptions need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SettingMoved {
    /// `search_path` no longer resolves an unqualified name to `public`.
    SearchPath,
    /// `standard_conforming_strings` is no longer `on`, so PostgreSQL reads a
    /// backslash in an ordinary string literal as the start of an escape and
    /// the proxy's parser does not.
    EscapeStrings,
}

/// The settings each statement of one SQL text moves, read from its **token
/// stream** and grouped per top-level statement, in order.
///
/// Not from the parsed statements, because they cannot see three of the four
/// forms that move a setting: sqlparser 0.53 rejects `SET SCHEMA 'tenant7'`
/// outright (it arrives as
/// [`Unprotected::Unparseable`](super::unprotected::Unprotected::Unparseable),
/// which under `warn` relays it), and `set_config('search_path', 'tenant7',
/// false)` is an ordinary function call that may sit anywhere in any
/// statement. Tokens see every form, and — unlike searching the raw text —
/// cannot mistake the same characters inside a string literal or a quoted
/// identifier for the keyword or the function name.
///
/// Grouping rather than flattening is what keeps a multi-statement batch
/// honest: a move belongs to the statements after it, not to the ones in front
/// of it, so `INSERT …; SET search_path …` still seals the insert.
///
/// `RESET` is deliberately absent: it restores whatever the role or the server
/// makes the default, which is the same value the connect-time assumption
/// already trusts, so treating it as a move would contradict that assumption
/// rather than tighten it.
///
/// `all` is the whole text's token stream, borrowed from the same
/// [`tokenize`](super::lexer::tokenize) call the parser is handed.
pub(super) fn settings_moved(all: &[TokenWithSpan]) -> Vec<Vec<SettingMoved>> {
    // Whitespace and comments are both `Whitespace` tokens, and neither
    // separates a keyword from what it applies to.
    let tokens: Vec<&Token> = all
        .iter()
        .map(|token| &token.token)
        .filter(|token| !matches!(token, Token::Whitespace(_)))
        .collect();

    // An empty run is the trailing semicolon, or one written twice; sqlparser
    // does not count either as a statement, so neither does this.
    tokens
        .split(|token| matches!(token, Token::SemiColon))
        .filter(|statement| !statement.is_empty())
        .map(statement_settings_moved)
        .collect()
}

/// The settings one statement moves. `tokens` are that statement's, with the
/// whitespace and the terminating semicolon already gone.
fn statement_settings_moved(tokens: &[&Token]) -> Vec<SettingMoved> {
    let mut moved = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let rest = &tokens[index + 1..];
        let found = match keyword(token) {
            // `SET` also opens the assignment list of an `UPDATE`, where the
            // name that follows is a column: only a statement-initial `SET` is
            // the session command.
            Some(word) if index == 0 && word.eq_ignore_ascii_case("set") => set_statement(rest),
            Some(word) if word.eq_ignore_ascii_case("set_config") => set_config_call(rest),
            _ => None,
        };
        if let Some(setting) = found {
            if !moved.contains(&setting) {
                moved.push(setting);
            }
        }
    }
    moved
}

/// The text of an unquoted word, to be compared case-insensitively — an
/// unquoted keyword or function name is folded by the server, so `SET` and
/// `set` are one word. A quoted word is an identifier the client chose, never a
/// keyword or a function name the server resolves.
///
/// Borrowed rather than lowercased into a `String`: this is called for every
/// token of every statement, and only a handful of them are ever compared.
fn keyword(token: &Token) -> Option<&str> {
    match token {
        Token::Word(word) if word.quote_style.is_none() => Some(word.value.as_str()),
        _ => None,
    }
}

/// `SET [SESSION | LOCAL] <name> {= | TO} <value…>`, and PostgreSQL's
/// `SET SCHEMA <value>` shorthand for a one-element `search_path`. `tokens`
/// starts just after the `SET`.
fn set_statement(tokens: &[&Token]) -> Option<SettingMoved> {
    let mut rest = tokens;
    if keyword(rest.first()?).is_some_and(|word| {
        word.eq_ignore_ascii_case("session") || word.eq_ignore_ascii_case("local")
    }) {
        rest = rest.get(1..)?;
    }
    let name = keyword(rest.first()?)?;
    rest = rest.get(1..)?;
    if name.eq_ignore_ascii_case("schema") {
        return moved_by("search_path", setting_values(rest));
    }
    if !matches!(rest.first()?, Token::Eq)
        && !keyword(rest.first()?).is_some_and(|word| word.eq_ignore_ascii_case("to"))
    {
        return None;
    }
    moved_by(name, setting_values(rest.get(1..)?))
}

/// `set_config('<setting>', '<value>', <is_local>)` — the function spelling of
/// `SET`, which reaches the server inside an ordinary query. `tokens` starts
/// just after the function name.
fn set_config_call(tokens: &[&Token]) -> Option<SettingMoved> {
    if !matches!(tokens.first()?, Token::LParen) {
        return None;
    }
    // A setting name that is not a literal could be `search_path`, and the
    // assumption that unqualified names resolve to `public` cannot survive a
    // change the proxy is unable to read.
    let Some(Token::SingleQuotedString(setting)) = tokens.get(1) else {
        return Some(SettingMoved::SearchPath);
    };
    if !matches!(tokens.get(2)?, Token::Comma) {
        return Some(SettingMoved::SearchPath);
    }
    moved_by(setting, setting_values(tokens.get(3..4)?))
}

/// Whether assigning `values` to `name` moves a tracked setting. `None` values
/// mean the assignment could not be read, which counts as a move: a setting
/// the proxy cannot evaluate is one it cannot keep assuming.
///
/// `name` is matched case-insensitively, the way the server resolves a setting
/// name — `SET Search_Path` and `set_config('SEARCH_PATH', …)` move the same
/// setting the lowercase spellings do.
fn moved_by(name: &str, values: Option<Vec<String>>) -> Option<SettingMoved> {
    if name.eq_ignore_ascii_case("search_path") {
        return (!is_default_search_path(values.as_deref())).then_some(SettingMoved::SearchPath);
    }
    if name.eq_ignore_ascii_case("standard_conforming_strings") {
        return (!is_on(values.as_deref())).then_some(SettingMoved::EscapeStrings);
    }
    None
}

/// The elements a setting is being assigned, stopping at the end of the
/// statement or of the enclosing call. A list may be written as separate
/// tokens (`SET search_path TO tenant7, public`) or as one string
/// (`set_config('search_path', 'tenant7, public', false)`), so both are split
/// down to the same shape. `None` means a token this cannot evaluate.
fn setting_values(tokens: &[&Token]) -> Option<Vec<String>> {
    let mut values = Vec::new();
    for token in tokens {
        match token {
            Token::SemiColon | Token::RParen => break,
            Token::Comma => {}
            Token::Word(word) if word.quote_style.is_some() => values.push(word.value.clone()),
            Token::Word(word) => values.push(word.value.to_ascii_lowercase()),
            Token::SingleQuotedString(text) => {
                values.extend(text.split(',').map(|part| part.trim().trim_matches('"').to_owned()))
            }
            Token::Number(number, _) => values.push(number.clone()),
            _ => return None,
        }
    }
    Some(values)
}

/// Whether a `search_path` value still leaves `public` as the schema an
/// unqualified name resolves to. `"$user", public` is PostgreSQL's own default
/// and stays trusted; anything else in front of `public` does not, because a
/// bare name may resolve there instead.
fn is_default_search_path(values: Option<&[String]>) -> bool {
    let Some(values) = values else { return false };
    values.iter().all(|name| name == "public" || name == "$user")
        && values.iter().any(|name| name == "public")
}

/// Whether a boolean setting is being turned on, as a `SET` spells it.
fn is_on(values: Option<&[String]>) -> bool {
    matches!(values, Some([value]) if is_on_value(value))
}

/// Whether one value spells boolean `on`, in any of the spellings PostgreSQL
/// accepts and in any case — `'ON'` in a `SET` and `ON` in a startup parameter
/// both turn the setting on. `DEFAULT` is not one of them: the default is
/// whatever the server was configured with, which the proxy cannot read.
///
/// Shared with the startup-packet scan in [`crate::session`], so the two halves
/// of "is this setting on" cannot drift apart.
pub(crate) fn is_on_value(value: &str) -> bool {
    ["on", "true", "t", "yes", "y", "1"].iter().any(|spelling| value.eq_ignore_ascii_case(spelling))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU8;
    use std::sync::Arc;

    use dbsec_core::blind_index;

    use crate::encrypt::lexer::parse_sql;
    use crate::encrypt::tests::*;
    use crate::encrypt::{QueryRewriter, StartupSettings};
    use crate::portal::SessionPortals;
    use crate::session::FrameAction;

    /// The mis-protection direction: a bare name in a session that moved
    /// `search_path` must not be sealed for `public.users`, because the value
    /// would land in a table the read path never resolves.
    #[test]
    fn moved_search_path_stops_sealing_unqualified_names() {
        let mut rewriter = rewriter(catalog(false));
        assert!(rewritten_query(&mut rewriter, "SET search_path TO myschema").is_none());
        assert!(
            rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('a@b.io')").is_none(),
            "an unqualified name must not be sealed once search_path moved"
        );
        // Qualifying the name puts it back beyond doubt.
        let sql =
            rewritten_query(&mut rewriter, "INSERT INTO public.users (email) VALUES ('a@b.io')")
                .expect("rewritten");
        assert!(!sql.contains("a@b.io"), "{sql}");
    }

    #[test]
    fn default_search_path_stays_trusted() {
        let mut rewriter = rewriter(catalog(false));
        for sql in ["SET search_path TO public", "SET search_path = \"$user\", public"] {
            assert!(rewritten_query(&mut rewriter, sql).is_none(), "{sql}");
        }
        let sql = rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('a@b.io')")
            .expect("rewritten");
        assert!(!sql.contains("a@b.io"), "{sql}");
    }

    /// `set_config` is the function spelling of `SET`, and it arrives as an
    /// ordinary `SELECT` — nothing in the parsed statement marks it as a
    /// session change. Missing it is not a plaintext leak but a silent
    /// mis-seal: the value is sealed for `public.users` while the row lands in
    /// `tenant7.users`, where the read path can never find it again.
    #[test]
    fn set_config_moves_search_path_the_same_way_set_does() {
        for sql in [
            "SELECT set_config('search_path', 'tenant7', false)",
            "SELECT pg_catalog.set_config('search_path', 'tenant7', false)",
            "SELECT set_config('SEARCH_PATH', 'tenant7', false)",
            // A list that no longer starts at `public`.
            "SELECT set_config('search_path', 'tenant7, public', false)",
            // A setting name the proxy cannot read could be `search_path`.
            "SELECT set_config($1, $2, false)",
            // Nested anywhere in the statement, not just the projection.
            "SELECT id FROM users WHERE id = (SELECT set_config('search_path', 'x', false))::int",
        ] {
            let mut rewriter = rewriter(catalog(false));
            assert!(rewritten_query(&mut rewriter, sql).is_none(), "{sql}");
            assert!(
                rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('a@b.io')")
                    .is_none(),
                "unqualified write was still sealed after: {sql}"
            );
        }
    }

    /// The value still has to be read: `set_config` back to the default leaves
    /// unqualified names resolving to `public`, so the write is sealed.
    #[test]
    fn set_config_back_to_the_default_stays_trusted() {
        let mut rewriter = rewriter(catalog(false));
        assert!(rewritten_query(
            &mut rewriter,
            "SELECT set_config('search_path', '\"$user\", public', false)"
        )
        .is_none());
        let sql = rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('a@b.io')")
            .expect("rewritten");
        assert!(!sql.contains("a@b.io"), "{sql}");
    }

    /// Reading the whole batch's tokens up front is what makes `SET SCHEMA`
    /// and `set_config` visible at all, but a move still belongs only to the
    /// statements after it. Flattening the batch would let a `SET` at its end
    /// retroactively unseal the write in front of it — a plaintext write under
    /// the default `warn`, for SQL the server executes in the other order.
    #[test]
    fn a_search_path_move_does_not_reach_back_over_the_writes_before_it() {
        let mut rewriter = rewriter(catalog(false));
        let sql = rewritten_query(
            &mut rewriter,
            "INSERT INTO users (email) VALUES ('a@b.io'); SET search_path TO tenant7",
        )
        .expect("rewritten");
        assert!(!sql.contains("a@b.io"), "the write before the move was not sealed: {sql}");

        // And it holds for everything after it, in the same batch or a later
        // one.
        assert!(
            rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('c@d.io')").is_none(),
            "the move did not stick"
        );
    }

    /// The other half of the same rule: a move does reach the statements that
    /// follow it inside its own batch.
    #[test]
    fn a_search_path_move_covers_the_writes_after_it_in_the_same_batch() {
        let mut rewriter = rewriter(catalog(false));
        assert!(
            rewritten_query(
                &mut rewriter,
                "SET search_path TO tenant7; INSERT INTO users (email) VALUES ('e@f.io')",
            )
            .is_none(),
            "a write after the move in the same batch must not be sealed"
        );
    }

    /// sqlparser 0.53 cannot parse `SET SCHEMA` at all, so it reaches the
    /// server as unparseable SQL and, under `warn`, is relayed. Reading the
    /// token stream rather than the AST is what keeps it tracked anyway.
    #[test]
    fn set_schema_moves_search_path_even_though_it_does_not_parse() {
        let mut rewriter = rewriter(catalog(false));
        assert!(parse_sql("SET SCHEMA 'tenant7'").is_err(), "the premise of this test");
        assert!(rewritten_query(&mut rewriter, "SET SCHEMA 'tenant7'").is_none());
        assert!(
            rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('a@b.io')").is_none(),
            "an unqualified name must not be sealed once SET SCHEMA moved search_path"
        );
    }

    /// `set_config` and `SET SCHEMA` are refused under `reject` exactly as
    /// `SET search_path` is, so an operator who pinned the search_path cannot
    /// have it moved out from under them by a spelling the proxy ignored.
    #[test]
    fn strict_mode_refuses_every_search_path_spelling() {
        for sql in [
            "SET search_path TO tenant7",
            "SET SCHEMA 'tenant7'",
            "SELECT set_config('search_path', 'tenant7', false)",
        ] {
            let mut strict = rewriter(strict_catalog(false));
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(refusal(&action).contains("search_path"), "{sql}");
        }
    }

    /// The word `set_config` inside a string literal or a quoted identifier is
    /// data, not a call: reading tokens rather than the raw text is what keeps
    /// these from refusing working SQL under `reject`.
    #[test]
    fn session_settings_are_not_read_out_of_literals_or_column_names() {
        for sql in [
            "SELECT id FROM users WHERE note = 'set_config(''search_path'', ''x'', false)'",
            "UPDATE audit SET search_path = 'tenant7' WHERE id = 1",
        ] {
            let mut strict = rewriter(strict_catalog(false));
            assert!(
                matches!(
                    strict.on_frame(b'Q', &query_frame(sql)).unwrap(),
                    FrameAction::Relay | FrameAction::Replace(_)
                ),
                "{sql}"
            );
        }
    }

    /// A sealed BYTEA value goes out as `E'\\x…'`, not `'\x…'`. The plain
    /// spelling is PostgreSQL's hex input syntax only while
    /// `standard_conforming_strings` is on; with it off the server applies
    /// backslash processing first and stores something else entirely. The
    /// escape-string form means the same bytes under either setting.
    #[test]
    fn sealed_bytea_literals_do_not_depend_on_standard_conforming_strings() {
        let mut rewriter = rewriter(catalog(true));
        let sql = rewritten_query(&mut rewriter, "UPDATE users SET email = 'bob@secret.test'")
            .expect("rewritten");
        let hex = sealed_hex(&sql).expect("sealed literal");
        assert!(sql.contains(&format!(r"E'\\x{hex}'")), "{sql}");
        assert!(
            !sql.contains(&format!(r"'\x{hex}'")),
            "a bare hex literal is still emitted: {sql}"
        );

        // The same holds for the blind-index literal a predicate is rewritten
        // to, which is BYTEA whatever the column's own stored form is.
        let sql = rewritten_query(&mut rewriter, "SELECT id FROM users WHERE email = 'a@b.io'")
            .expect("rewritten");
        let index = blind_index::compute(&crate::rows::tests::INDEX_KEY, b"a@b.io");
        assert!(sql.contains(&sealed_literal(&index)), "{sql}");
    }

    /// Turning the setting off is still reported: the proxy's own reading of
    /// the *client's* literals diverges from the server's from that point on,
    /// which no choice of output encoding can fix.
    #[test]
    fn turning_standard_conforming_strings_off_is_an_unprotected_site() {
        for sql in [
            "SET standard_conforming_strings = off",
            "SET standard_conforming_strings TO 'off'",
            "SET SESSION standard_conforming_strings = false",
            "SELECT set_config('standard_conforming_strings', 'off', false)",
        ] {
            let mut strict = rewriter(strict_catalog(false));
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(refusal(&action).contains("standard_conforming_strings"), "{sql}");
        }
    }

    /// Under the default `warn` the session carries on, and the write that
    /// follows is still sealed in the setting-independent form.
    #[test]
    fn a_write_after_standard_conforming_strings_off_is_still_sealed_readably() {
        let mut rewriter = rewriter(catalog(false));
        assert!(rewritten_query(&mut rewriter, "SET standard_conforming_strings = off").is_none());
        let sql = rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('a@b.io')")
            .expect("rewritten");
        assert!(sql.contains(SEALED_PREFIX), "{sql}");
        assert_eq!(open_hex_literal(&sql, false), b"a@b.io");
    }

    /// Once the setting is off, a literal that actually carries a backslash is
    /// one the proxy and the server read differently. Sealing it would store
    /// the proxy's reading, which nothing downstream could tell apart from a
    /// correct value, so the literal is reported instead and the data stays
    /// intact. Literals without a backslash mean the same thing either way and
    /// are still sealed.
    #[test]
    fn a_backslash_literal_after_the_setting_moved_is_reported_not_guessed_at() {
        let mut lenient = rewriter(catalog(true));
        assert!(rewritten_query(&mut lenient, "SET standard_conforming_strings = off").is_none());

        assert!(
            rewritten_query(&mut lenient, r"INSERT INTO users (email) VALUES ('a\nb@secret.test')")
                .is_none(),
            "a literal the two sides read differently must not be sealed"
        );
        assert!(
            rewritten_query(&mut lenient, r"SELECT id FROM users WHERE email = 'a\nb@secret.test'")
                .is_none(),
            "nor indexed"
        );

        // No backslash, no disagreement.
        let sql = rewritten_query(&mut lenient, "INSERT INTO users (email) VALUES ('a@b.io')")
            .expect("rewritten");
        assert_eq!(open_hex_literal(&sql, true), b"a@b.io");

        // Under `reject` the setting change is refused outright, so the state
        // this guards against is unreachable in the mode that enforces the
        // invariant.
        let mut strict = rewriter(strict_catalog(true));
        let action =
            strict.on_frame(b'Q', &query_frame("SET standard_conforming_strings = off")).unwrap();
        assert!(refusal(&action).contains("standard_conforming_strings"));
    }

    /// Turning it *on* is the state the proxy already assumes, so it is not a
    /// site at all — a signal that fires on correct SQL stops being read.
    #[test]
    fn turning_standard_conforming_strings_on_is_not_reported() {
        for sql in [
            "SET standard_conforming_strings = on",
            "SET standard_conforming_strings TO true",
            "SET standard_conforming_strings = 1",
        ] {
            let mut strict = rewriter(strict_catalog(false));
            assert!(
                matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
                "{sql}"
            );
        }
    }

    /// A session that started with a `search_path` in its startup packet is
    /// untrusted from the first statement.
    #[test]
    fn untrusted_session_never_seals_unqualified_names() {
        let mut rewriter = QueryRewriter::new(
            catalog(false),
            SessionPortals::new(),
            None,
            Arc::new(AtomicU8::new(b'I')),
            StartupSettings { search_path_trusted: false, ..StartupSettings::default() },
        );
        assert!(
            rewritten_query(&mut rewriter, "INSERT INTO users (email) VALUES ('a@b.io')").is_none()
        );
    }

    /// The other half of the same story: a startup packet that turned
    /// `standard_conforming_strings` off leaves the session in the state a
    /// mid-session `SET` would have left it in — reported once, on the first
    /// statement, and with the client's own backslash literals no longer read
    /// as the server reads them.
    #[test]
    fn a_startup_packet_that_turned_standard_conforming_strings_off_is_reported_once() {
        let started_off = |catalog| {
            QueryRewriter::new(
                catalog,
                SessionPortals::new(),
                None,
                Arc::new(AtomicU8::new(b'I')),
                StartupSettings { escape_strings: true, ..StartupSettings::default() },
            )
        };

        // Under `reject` the divergence is refused on the first statement,
        // exactly as the `SET` spelling is.
        let mut strict = started_off(strict_catalog(false));
        let action = strict.on_frame(b'Q', &query_frame("SELECT 1")).unwrap();
        assert!(refusal(&action).contains("standard_conforming_strings"));

        // Once, though: the report is the setting moving, not every statement
        // that follows it.
        assert!(matches!(
            strict.on_frame(b'Q', &query_frame("SELECT 1")).unwrap(),
            FrameAction::Relay
        ));

        // Under `warn` the session carries on, with a literal the two sides
        // read differently left alone rather than sealed as the proxy read it.
        let mut lenient = started_off(catalog(true));
        assert!(
            rewritten_query(&mut lenient, r"INSERT INTO users (email) VALUES ('a\nb@secret.test')")
                .is_none(),
            "a literal the two sides read differently must not be sealed"
        );
        let sql = rewritten_query(&mut lenient, "INSERT INTO users (email) VALUES ('a@b.io')")
            .expect("rewritten");
        assert_eq!(open_hex_literal(&sql, true), b"a@b.io");
    }

    /// A startup packet that moved nothing reports nothing: a signal that fires
    /// on a correctly configured session stops being read.
    #[test]
    fn a_default_startup_packet_reports_nothing() {
        let mut strict = rewriter(strict_catalog(false));
        assert!(matches!(
            strict.on_frame(b'Q', &query_frame("SELECT 1")).unwrap(),
            FrameAction::Relay
        ));
    }
}
