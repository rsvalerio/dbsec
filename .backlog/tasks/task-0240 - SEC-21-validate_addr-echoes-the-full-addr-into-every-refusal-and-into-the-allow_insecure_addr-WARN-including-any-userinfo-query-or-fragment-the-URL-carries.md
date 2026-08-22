---
id: TASK-0240
title: >-
  SEC-21: validate_addr echoes the full addr into every refusal and into the
  allow_insecure_addr WARN, including any userinfo, query or fragment the URL
  carries
status: Triage
assignee: []
created_date: '2026-08-21 19:51'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/vault/src/lib.rs
  - crates/vault/src/source.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/vault/src/lib.rs:236` (also `crates/vault/src/lib.rs:243`, `crates/vault/src/lib.rs:250`, `crates/vault/src/lib.rs:256`, `crates/vault/src/source.rs:455`)

**What**: `validate_addr` parses `addr` into a `url::Url` and then formats the *original string* (`self.addr`) into the not-a-URL error, the plaintext-http error, the unsupported-scheme error and the `tracing::warn!(addr = self.addr, ..)` line; `client_settings` does the same in its `backend_error` message. The doc comment argues this is safe because "it is an endpoint, and the credential beside it lives in `token`/`token_file`" — but a URL can carry a credential itself (`https://user:s.token@bao.internal:8200`), and an operator who copied a Vault address out of a `curl` line or a proxy URL is exactly the person whose config is being refused and logged. Nothing rejects userinfo, a query string or a fragment, none of which are meaningful for a Vault address.

**Why it matters**: SEC-21 — no secrets in error messages or logs. The cheap, complete fix is on the validation side: refuse an `addr` with `username()`/`password()` set (or with a query/fragment), and render the parsed URL's origin (`scheme://host:port`) rather than the raw input in every message. That also gives the refusal a normalised address to point at instead of whatever whitespace or trailing slash the operator typed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 validate_addr refuses an addr carrying userinfo (and documents query/fragment handling), with a test
- [ ] #2 Every refusal and the allow_insecure_addr WARN render the scheme/host/port of the parsed URL, never the raw addr string; a test feeds https://u:p@host and asserts neither u nor p appears in the message or event
<!-- AC:END -->
