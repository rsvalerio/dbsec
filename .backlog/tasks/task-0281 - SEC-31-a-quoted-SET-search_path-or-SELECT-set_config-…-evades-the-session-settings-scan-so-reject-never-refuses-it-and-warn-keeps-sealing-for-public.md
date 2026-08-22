---
id: TASK-0281
title: >-
  SEC-31: a quoted SET "search_path" or SELECT "set_config"(…) evades the
  session-settings scan, so reject never refuses it and warn keeps sealing for
  public
status: Triage
assignee: []
created_date: '2026-08-22 00:46'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/settings.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/settings.rs:100`

**What**: `keyword()` (crates/proxy/src/encrypt/settings.rs:100-105) returns `None` for any `Token::Word` with a quote style, and both readers depend on it: `set_statement` reads the setting name through `keyword(rest.first()?)?` (settings.rs:117), and `statement_settings_moved` recognises the function call only via `keyword(token)` == `set_config` (settings.rs:81). PostgreSQL's grammar takes the `SET` var_name as a ColId and the function name as an IDENT, both of which may be double-quoted, and a lowercase quoted identifier is the same object as the bare spelling — so `SET "search_path" TO tenant7` and `SELECT "set_config"('search_path', 'tenant7', false)` move the setting on the server and produce no `SettingMoved` here. The doc comment on `keyword` (settings.rs:93-96) asserts a quoted word is 'never a keyword or a function name the server resolves', which is true for keywords and false for the setting name and the function name. The same gap applies to `SET "standard_conforming_strings" = off`.

**Why it matters**: The module exists so that a moved `search_path` stops the rewrite from sealing unqualified names against `public.users` and so that under `reject` a pinned search_path cannot be moved by a spelling the proxy ignored (settings.rs:352-356). A quoted spelling is exactly such a spelling: under `reject` the statement relays instead of being refused, and under `warn` every following unqualified write is sealed with the `public.users` context while the row lands in `tenant7.users`. Turning `standard_conforming_strings` off the same way leaves the proxy reading backslash literals differently from the server with no signal.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `set_statement` accepts the setting name as either an unquoted word or a double-quoted identifier (quoted = verbatim, unquoted = lowercased), so `SET "search_path" TO x` and `SET "standard_conforming_strings" = off` are classified the same way as their bare spellings, while `SET "Search_Path"` (a different identifier) stays untracked
- [ ] #2 `statement_settings_moved` recognises `"set_config"` (quoted, lowercase) and `pg_catalog."set_config"` as the function call
- [ ] #3 The `keyword` doc comment states the actual rule (quoted identifiers are compared verbatim, unquoted ones case-insensitively)
- [ ] #4 Tests in settings.rs drive the quoted spellings under both `warn` (the following unqualified INSERT is not sealed) and `reject` (the statement is refused), and show `SET "Search_Path"` does not fire
<!-- AC:END -->
