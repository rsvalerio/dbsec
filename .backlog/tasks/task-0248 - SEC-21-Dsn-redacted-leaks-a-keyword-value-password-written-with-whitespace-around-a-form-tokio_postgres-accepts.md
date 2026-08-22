---
id: TASK-0248
title: >-
  SEC-21: Dsn::redacted leaks a keyword/value password written with whitespace
  around =, a form tokio_postgres accepts
status: Triage
assignee: []
created_date: '2026-08-21 19:54'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/config.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/config.rs:170`

**What**: `mask_password_parameters` only treats a token as a key when the byte immediately after it is `=`:
```rust
let key = &input[key_start..i];
out.push_str(key);
if i >= bytes.len() || bytes[i] != b'=' {
    continue;
}
```
tokio_postgres's parser (`Parser::parameter`) does `skip_ws(); keyword(); skip_ws(); eat('=')?; skip_ws(); value()`, so `host=db password = hunter2 dbname=app` parses. `Dsn::redacted` (config.rs:92-97) checks the string parses, then `redact_dsn` sees `password` as a bare key with no `=`, emits it, the space, treats `=` as an empty key and `hunter2` as another bare key — printing the password verbatim. `Debug` (config.rs:115) and `Display` (config.rs:123) route through `redacted()`. A related partial leak: a backslash-escaped space (`password=hun\ ter2`) is masked only up to the first raw space, emitting `<redacted> ter2`.

**Why it matters**: this is the exact shape TASK-0047 was closed on, but the redaction grammar is narrower than the grammar the DSN is validated against, so a DSN that passes `Config::validate` and connects can print its password into the config Debug output, the `dsn` field of any tracing line, or an error message. `password = '...'` with spaces is a common libpq spelling.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Dsn::redacted() masks the password for every keyword/value spelling tokio_postgres accepts (whitespace incl. tabs/newlines around =, quoted values, backslash-escaped spaces), preferably by rendering the redacted form from the parsed tokio_postgres Config
- [ ] #2 debugging_a_dsn_masks_the_password_and_keeps_the_endpoint gains cases for 'password = hunter2', tab-separated quoted value and 'password=hun\ ter2', asserting the password never appears in {:?} or {}
<!-- AC:END -->
