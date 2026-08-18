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
/// outright (it arrives as [`Unprotected::Unparseable`], which under `warn`
/// relays it), and `set_config('search_path', 'tenant7', false)` is an
/// ordinary function call that may sit anywhere in any statement. Tokens see
/// every form, and — unlike searching the raw text — cannot mistake the same
/// characters inside a string literal or a quoted identifier for the keyword
/// or the function name.
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
/// `all` is the whole text's token stream, borrowed from the same [`tokenize`]
/// call the parser is handed.
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
