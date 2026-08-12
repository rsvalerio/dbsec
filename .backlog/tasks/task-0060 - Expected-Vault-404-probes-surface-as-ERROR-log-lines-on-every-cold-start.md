---
id: TASK-0060
title: Expected Vault 404 probes surface as ERROR log lines on every cold start
status: Done
assignee:
  - TASK-0065
created_date: '2026-08-12 16:14'
updated_date: '2026-08-12 19:21'
labels:
  - code-review-rust
  - observability
  - vault
dependencies: []
modified_files:
  - crates/proxy/src/vault.rs
  - crates/proxy/src/main.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/vault.rs`

**What**: Resolving an index key for the first time probes two paths that are *expected* to be absent on a greenfield deployment: `{path}/index_keys/{name}` and then the pre-versioning shared map at `{path}/index_keys`. Both 404s are normal control flow — `is_not_found` maps them to `Ok(None)` and the key is minted — but `vaultrs`/`rustify` log each one at **ERROR** from inside the library before returning:

```text
ERROR request{method=GET path=secret/data/.../index_keys/public.users_vault.email}: rustify::client: error=Server returned error
ERROR ...: vaultrs::api: error=The Vault server returned an error (status code 404)
```

Observed live during `make e2e-vault`: a four-column table produces roughly six ERROR lines per cold start, immediately followed by `INFO minted new deterministic index key`. The same happens on the DEK path for an unknown key id.

**Why it matters**: A clean, fully successful startup looks like a failing one. Operators watching for ERROR — or an alerting rule keyed on it — get paged for the proxy working exactly as designed, and the noise buries the ERROR lines that do matter (a real 5xx, a revoked token, a permission denial), which is precisely the distinction [[task-0006]] was filed to preserve. It also makes the mint path hard to read in a log capture.

The fix is on the tracing side, not the key logic: the levels come from the `vaultrs`/`rustify` targets, so a subscriber filter (e.g. `vaultrs=warn,rustify=warn` in the default `EnvFilter`) would suppress them, at the cost of also hiding genuine library errors — so the proxy should log its own error context at the call site first (which it already does via `Error::KeySource`) and then quiet the library targets. Worth confirming whether a `HEAD`/list probe or `kv2::read_metadata` avoids the ERROR path entirely.

**Origin**: discovered during TASK-0052 while fixing TASK-0006/TASK-0007, by running `make e2e-vault` against a live OpenBao.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 An ordinary cold start that mints index keys produces no ERROR-level log lines
- [x] #2 A genuine Vault failure (5xx, 403, revoked token) is still visible at ERROR
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Default subscriber filter is now `info,vaultrs=off,rustify=off` (DEFAULT_LOG_FILTER in main.rs): the expected-absence 404 probes are logged at ERROR from inside vaultrs/rustify, so those targets are silenced rather than lowered. AC2 is kept by the handling site instead: session failures caused by the key backend (KeyBackend/KeySource) now log at ERROR via log_session_error, everything else stays WARN, and startup failures already logged at ERROR. Pinned by two unit tests in main.rs. RUST_LOG, when set, still owns the filter entirely.

Verified live against a dev-mode OpenBao (make e2e-vault): a cold start now mints three index keys with zero ERROR lines. That run also required fixing the e2e config fixture, which wrote on_unprotected after the [vault] table so the proxy refused the config.
<!-- SECTION:NOTES:END -->
