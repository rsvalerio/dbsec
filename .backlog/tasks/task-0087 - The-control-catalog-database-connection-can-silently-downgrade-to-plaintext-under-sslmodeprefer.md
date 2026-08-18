---
id: TASK-0087
title: >-
  The control (catalog) database connection can silently downgrade to plaintext
  under sslmode=prefer
status: Done
assignee:
  - TASK-0119
created_date: '2026-08-14 14:06'
updated_date: '2026-08-18 09:31'
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
- [x] #1 With upstream TLS configured, a control_dsn weaker than sslmode=require is refused or upgraded
- [x] #2 An MITM answering N to the control connection SSLRequest cannot force a plaintext control session
- [x] #3 A test exercises the control connection with a downgrade-attempting endpoint
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in TASK-0119 (branch code-review/TASK-0119). `Config::validate` now calls `check_control_dsn_is_not_downgradeable` whenever `[tls.upstream]` is configured: a `control_dsn` parsing to `sslmode=disable` or `sslmode=prefer` (including by omission, which is tokio-postgres' default) is refused with a message naming `sslmode=require`. Refused rather than rewritten — the DSN arrives in either of the two shapes tokio-postgres accepts and rewriting a string carrying a password is the worse trade. An unparseable `control_dsn` is refused too, without echoing the string (the parse error quotes the offending fragment, which is where the password lives). Modes at least as strict as `require` are accepted by falling through, so a future `SslMode` variant is not refused by a stale allow-list.

AC #3 is satisfied by `resolve::tests::a_control_endpoint_that_strips_tls_gets_no_plaintext_session`: a TCP listener answers `N` to the SSLRequest and holds the socket open, so a client willing to downgrade would have a live plaintext connection to downgrade onto; with `sslmode=require` the connect fails immediately instead. Config side: `config::tests::a_downgradeable_control_dsn_is_refused_once_upstream_tls_is_configured` and `config::tests::an_unparseable_control_dsn_is_refused_without_being_echoed`.

Without `[tls.upstream]` the control hop is deliberately left alone: the operator has asked for no TLS on the data hop either, and holding one hop to a bar the rest of the deployment does not meet only breaks working plaintext deployments.
<!-- SECTION:NOTES:END -->
