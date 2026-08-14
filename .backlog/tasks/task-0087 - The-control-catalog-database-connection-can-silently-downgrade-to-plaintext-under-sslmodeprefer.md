---
id: TASK-0087
title: >-
  The control (catalog) database connection can silently downgrade to plaintext
  under sslmode=prefer
status: Triage
assignee: []
created_date: '2026-08-14 14:06'
labels:
  - security-review
  - security
  - tls
dependencies: []
modified_files:
  - crates/proxy/src/resolve.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/resolve.rs:189-196` (control connect), contrast `crates/proxy/src/session.rs:259-271` (data hop).

**What**: the data hop sends SSLRequest and hard-fails on anything but `S` (verify-full, no downgrade). The control connection instead hands the same rustls `ClientConfig` to `tokio_postgres::connect` and lets the DSN decide `sslmode`. tokio-postgres defaults to `sslmode=prefer`: if the server (or an active MITM stripping TLS) answers `N`, the connection proceeds in plaintext with no error. Nothing forces `sslmode>=require` on `control_dsn`. Verified against source.

**Why it matters**: the control connection carries the control user's password and performs the catalog resolution that decides which columns are protected. With `[tls.upstream]` configured, the data hop is downgrade-proof while the control hop — the more sensitive one — is downgradeable. (When TLS *is* negotiated the cert is verified verify-full; the gap is the silent fallback to no TLS.)

**Fix shape**: reject or rewrite a `control_dsn` whose `sslmode` is weaker than `require` whenever `[tls.upstream]` is set.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 With upstream TLS configured, a control_dsn weaker than sslmode=require is refused or upgraded
- [ ] #2 An MITM answering N to the control connection SSLRequest cannot force a plaintext control session
- [ ] #3 A test exercises the control connection with a downgrade-attempting endpoint
<!-- AC:END -->
