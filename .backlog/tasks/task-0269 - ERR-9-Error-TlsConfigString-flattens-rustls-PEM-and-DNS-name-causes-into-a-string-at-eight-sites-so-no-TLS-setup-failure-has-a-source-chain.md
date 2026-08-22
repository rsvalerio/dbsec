---
id: TASK-0269
title: >-
  ERR-9: Error::TlsConfig(String) flattens rustls, PEM and DNS-name causes into
  a string at eight sites, so no TLS setup failure has a source chain
status: Triage
assignee: []
created_date: '2026-08-22 00:38'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/proxy/src/main.rs
  - crates/proxy/src/tls.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/main.rs:270`

**What**: `Error::TlsConfig(String)` (crates/proxy/src/main.rs:270-271) is the target of `format!("...: {e}")` conversions at crates/proxy/src/tls.rs:122 (`rustls::Error` from `with_single_cert`), tls.rs:133 (`RootCertStore::add`), tls.rs:144 (`InvalidDnsNameError`), tls.rs:56/62 (provider install), tls.rs:169/171/173 (`pem::Error` and the empty-bundle case) and tls.rs:187 (`pem::Error`). Each discards the typed cause, so `diag::chain` — which the workspace adopted in TASK-0138 precisely so `#[source]` causes are rendered — has nothing to walk, and no caller or test can match on *which* TLS failure occurred. TASK-0251 covers the `InvalidConfig(String)` catch-alls; this is the sibling variant.

**Why it matters**: Startup TLS failures are the operator-facing path where 'certificate/key mismatch' vs 'unreadable PEM' vs 'bad hostname' matters; stringly-typed variants (ERR-10) also mean the tests in tls.rs assert on substrings rather than variants.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `Error::TlsConfig` becomes a variant carrying `what`/`path` plus a `#[source]` (`rustls::Error`, `pem::Error`, `InvalidDnsNameError`, or a small `TlsConfigError` enum), with the provider-policy mismatch as its own variant
- [ ] #2 `diag::chain` of a cert/key mismatch renders the rustls cause beneath the proxy's context, pinned by a test
- [ ] #3 tls.rs tests match on variants where they currently match on message substrings
<!-- AC:END -->
