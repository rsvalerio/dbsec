---
id: TASK-0069
title: >-
  ERR-11: TlsContext::from_config takes an unvalidated Config, so the downstream
  key permission check is only enforced by convention
status: Triage
assignee: []
created_date: '2026-08-12 19:12'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/proxy/src/tls.rs
  - crates/proxy/src/main.rs
  - crates/proxy/src/session.rs
  - crates/proxy/src/resolve.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/tls.rs:104`

**What**: `TlsContext::from_config` takes `&Config`, not the `&ValidatedConfig` that `Config::validated` hands out. The SEC-29 permission check on `[tls.downstream] key` lives in `Config::validate`, so a `TlsContext` built from a `Config` that never went through validation reads the private key with no mode check at all. `main.rs` does validate first, so the production path is safe today — but the guarantee is upheld by call-site convention rather than by the type, which is exactly the shape TASK-0041 removed from `serve()`.

**Why it matters**: The check silently does not apply to any future caller that builds a `Config` directly (several test call sites already do), so the protection can be lost without any test failing. Encoding it in the signature makes "the key's mode was proved safe" a precondition the compiler enforces.

**Origin**: discovered during TASK-0067 while fixing TASK-0063.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 TlsContext is constructible only from a config whose validation has run, so the [tls.downstream] key permission check cannot be bypassed by a call site
- [ ] #2 Existing call sites in main.rs, session.rs and resolve.rs are updated, and no test constructs a TlsContext by a path that skips validation
<!-- AC:END -->
