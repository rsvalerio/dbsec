---
id: TASK-0257
title: >-
  SEC-11: a DO block that calls set_config('search_path', ...) moves the
  server's search_path invisibly under warn
status: Triage
assignee: []
created_date: '2026-08-21 19:55'
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
**File**: `crates/proxy/src/encrypt/settings.rs:76`

**What**:
```rust
let found = match keyword(token) {
    Some(word) if index == 0 && word.eq_ignore_ascii_case("set") => set_statement(rest),
    Some(word) if word.eq_ignore_ascii_case("set_config") => set_config_call(rest),
    _ => None,
};
```
The scan only sees `SET`/`set_config` as bare `Token::Word`s. `DO $$ BEGIN PERFORM set_config('search_path', 'tenant7', false); END $$` (or `EXECUTE 'SET search_path ...'` inside it) carries the call inside a `DollarQuotedString` token, so nothing is tracked. sqlparser cannot parse `DO`, so under `reject` the block is refused as `Unparseable`; under the default `warn` it is relayed and the session's `search_path` moves with `search_path_trusted` still `true` — the silent mis-seal TASK-0091 fixed for `set_config`, reached by another spelling (`SET search_path` executed server-side is SESSION-scoped and persists).

**Why it matters**: a subsequent `INSERT INTO users (email) ...` is sealed for `public.users` while the row lands in `tenant7.users`, unreadable by the read path.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A DO block (statement-initial DO keyword followed by a dollar-quoted/string body) whose body mentions set_config, SET search_path, SET SCHEMA or standard_conforming_strings is treated as a move of that setting, or any DO body is treated conservatively as moving both tracked settings
- [ ] #2 Test: after DO $$ BEGIN PERFORM set_config('search_path','t',false); END $$ under warn, an unqualified write is no longer sealed and is a SearchPath site
<!-- AC:END -->
