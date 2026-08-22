---
id: TASK-0204
title: >-
  ERR-9: VaultConfig::resolve_token and check_token_file flatten the core
  secret-file error into Error::Config(String), and Error::Config is
  stringly-typed for every config refusal
status: Triage
assignee: []
created_date: '2026-08-21 19:36'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/vault/src/lib.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/vault/src/lib.rs:260` (also `crates/vault/src/lib.rs:286`, `crates/vault/src/lib.rs:68`)

**What**: `resolve_token` and `check_token_file` map the `dbsec_core::Error` returned by `check_secret_file_mode` through `.map_err(|e| Error::Config(e.to_string()))`, so the typed cause (the mode check's own variant, and any `io::Error` it carries) is gone by the time the error leaves the crate — `Error::source()` is `None`. More broadly, `Error::Config(String)` is the single variant used for five unrelated refusals (bad URL, plaintext `http`, unsupported scheme, zero timeout, zero-or-two token sources, permissive token-file mode), so a caller can only tell them apart by substring-matching the message. TASK-0078 fixed the `read_to_string` branch (now `Error::TokenFile`) but the mode-check branch still flattens.

**Why it matters**: The proxy's diagnostics render error chains via `diag::chain`; a flattened cause shows one line where the core error would have shown the path and the `io::Error` kind. For a published crate, a caller (or a test) that wants to react to "insecure address" differently from "no token configured" has no variant to match on (ERR-2/ERR-10).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The mode-check failure in resolve_token/check_token_file keeps its dbsec_core::Error reachable through Error::source() (e.g. an Error::TokenFileMode { path, source } or a #[from]/#[source] wrapper), with a test that downcasts the source
- [ ] #2 Error::Config is split into variants (or carries an enum reason) that let callers distinguish at least: not-a-URL, plaintext-http-refused, unsupported-scheme, no-token-source/two-token-sources, zero-timeout
- [ ] #3 Existing proxy tests asserting on message substrings still pass or are updated to match variants
<!-- AC:END -->
