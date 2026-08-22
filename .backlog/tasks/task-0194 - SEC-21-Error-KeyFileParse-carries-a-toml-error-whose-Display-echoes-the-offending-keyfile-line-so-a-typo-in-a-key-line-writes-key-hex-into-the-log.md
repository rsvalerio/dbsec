---
id: TASK-0194
title: >-
  SEC-21: Error::KeyFileParse carries a toml error whose Display echoes the
  offending keyfile line, so a typo in a key line writes key hex into the log
status: Triage
assignee: []
created_date: '2026-08-21 19:31'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/core/src/keys.rs
  - crates/core/src/lib.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/keys.rs:184` (also `crates/core/src/lib.rs:265`, `crates/core/src/diag.rs:775`)

**What**: `FileKeySource::load` maps `toml::from_str` failures to `Error::KeyFileParse { source: toml::de::Error }` and keeps the toml error as `#[source]`. `toml_edit::TomlError`'s `Display` (toml_edit 0.22.27 `src/error.rs:87-112`) renders `TOML parse error at line N, column M` followed by the *full text of the offending line* with a caret under it. In a keyfile every non-`active` line is `<key id hex> = "<64 hex chars of DEK or index key>"`, so a malformed key line — a missing closing quote, a stray character — reproduces the key material in the error text. `diag::chain` walks `source()` precisely so causes reach the operator, and the keys.rs test `malformed_keyfile_keeps_the_toml_error_as_a_cause` pins the cause in place. The proxy's own config-parse error deliberately drops the toml cause for exactly this reason (see the `diag.rs` module docs), but the keyfile path in this crate does not. A second exposure: `TomlError` stores the whole raw document (`raw: Option<String>`) for that rendering, so the complete keyfile outlives the `Zeroizing` read buffer inside the error value and is freed unwiped.

**Why it matters**: Every DEK and deterministic index key the deployment has can land in a log line, log shipper and crash report on the one occasion an operator mistypes the keyfile — the moment they are most likely to be staring at logs. It undoes the care taken elsewhere (`Key`'s redacting `Debug`, the zeroizing read buffer, the hand-rolled hex writer).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A malformed key line in a keyfile produces an error whose full rendered chain (top-level Display, every source(), and diag::chain output) contains no hex substring from the file
- [ ] #2 The error still tells the operator the line and column of the parse failure (span preserved, source text dropped)
- [ ] #3 No intact copy of the keyfile text is retained inside the returned error value
- [ ] #4 A test feeds a keyfile with a syntactically broken key line and asserts the rendered chain does not contain the key hex
<!-- AC:END -->
