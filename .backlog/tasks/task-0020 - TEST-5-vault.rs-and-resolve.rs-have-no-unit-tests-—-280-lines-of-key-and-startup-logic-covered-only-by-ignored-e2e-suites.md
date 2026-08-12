---
id: TASK-0020
title: >-
  TEST-5: vault.rs and resolve.rs have no unit tests — 280 lines of key and
  startup logic covered only by ignored e2e suites
status: Done
assignee:
  - TASK-0052
created_date: '2026-08-11 19:15'
updated_date: '2026-08-12 16:10'
labels:
  - code-review-rust
  - tests
  - vault
  - resolve
dependencies: []
modified_files:
  - crates/proxy/src/vault.rs
  - crates/proxy/src/resolve.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/vault.rs`, `crates/proxy/src/resolve.rs`

**What**: Every other module in the crate carries a `#[cfg(test)]` module — `config.rs`, `columns.rs`, `encrypt.rs`, `rows.rs`, `session.rs`, `tls.rs`. These two do not:

| File | Lines | Inline tests |
|---|---|---|
| `crates/proxy/src/vault.rs` | 189 | none |
| `crates/proxy/src/resolve.rs` | 92 | none |

Their only coverage is `tests/e2e_vault.rs`, which is `#[ignore]`d behind `make e2e-vault` and needs both a live OpenBao and a live Postgres. So on an ordinary `cargo test` — and on any CI job that does not stand up both services — these two files execute zero assertions.

Specific untested behaviour, all of it failure-path:

- `decode_key_b64` / `decode_key_hex` (`vault.rs:170-189`) — pure functions with three branches each (bad encoding, wrong length, success) and explicit zeroization of the intermediate buffer. Testable with no I/O at all; there is no reason these are uncovered.
- `fetch_or_create_index_key`'s mint-vs-reuse branch, which is where [[task-0006]] and [[task-0007]] both live.
- `key()`'s cache-hit vs cache-miss paths.
- `resolve_columns`' `ColumnNotFound` error and the `column.readable || column.mask.is_some()` filter at `resolve.rs:52-58` — the logic deciding which columns the read path acts on at all. A regression here silently stops decrypting a column, which is exactly the failure this proxy must not have.

**Why it matters**: These are the two modules where a bug is least visible. A wrong `readable` filter means a column quietly stops being decrypted; a wrong key decode means a startup failure or, worse, a key silently derived from truncated material. Both currently depend on a suite that most contributors will never run locally. The pure functions and the filter logic need no external services and should be covered inline; the Vault client interactions need either a trait seam or a `wiremock`-style double (TEST-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 decode_key_b64 and decode_key_hex have unit tests covering bad encoding, wrong length, and success
- [x] #2 The readable/mask filter in resolve_columns is covered by a unit test, including a column that is neither readable nor masked and must not enter the map
- [x] #3 The mint-vs-reuse branch of the index-key path is tested behind a seam that does not require a live Vault
- [x] #4 cargo test with no external services reports non-zero coverage for both files
<!-- AC:END -->
