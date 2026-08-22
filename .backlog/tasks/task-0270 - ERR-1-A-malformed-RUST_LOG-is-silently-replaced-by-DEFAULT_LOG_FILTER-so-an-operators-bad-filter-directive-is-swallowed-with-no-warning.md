---
id: TASK-0270
title: >-
  ERR-1: A malformed RUST_LOG is silently replaced by DEFAULT_LOG_FILTER, so an
  operator's bad filter directive is swallowed with no warning
status: Triage
assignee: []
created_date: '2026-08-22 00:38'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/proxy/src/main.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/main.rs:637`

**What**: crates/proxy/src/main.rs:637-640 does `EnvFilter::try_from_default_env().unwrap_or_else(|_| DEFAULT_LOG_FILTER.into())`. `try_from_default_env` returns `Err` both when `RUST_LOG` is unset and when it is set but unparsable; the code treats both identically and discards the error. An operator who sets `RUST_LOG=dbsec=debug,vaultrs=debug,` (trailing comma) or any other invalid directive gets the default `info,vaultrs=off,rustify=off` filter, with nothing on stderr saying why the debug output they asked for never appears.

**Why it matters**: The `DEFAULT_LOG_FILTER` doc (main.rs:59-84) promises 'An operator who sets RUST_LOG owns the filter completely'; on a parse error that promise is silently broken, which is most likely to happen exactly when someone is debugging a Vault or TLS problem and turning `vaultrs=debug` back on.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The unset case uses `DEFAULT_LOG_FILTER`; the set-but-invalid case either fails startup with a usage-style error naming the bad directive, or falls back and emits a WARN quoting the parse error
- [ ] #2 A test covers the invalid-directive branch by calling the filter-construction helper with an explicit string rather than the process environment
<!-- AC:END -->
