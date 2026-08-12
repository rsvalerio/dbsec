---
id: TASK-0006
title: >-
  SEC-31: a failed Vault KV read silently mints fresh index keys and overwrites
  every stored one
status: Done
assignee:
  - TASK-0052
created_date: '2026-08-11 19:12'
updated_date: '2026-08-12 16:10'
labels:
  - code-review-rust
  - security
  - vault
dependencies: []
modified_files:
  - crates/proxy/src/vault.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**Severity**: Critical (filed at the CLI's highest available priority, `high`)

**File**: `crates/proxy/src/vault.rs:123-143`

**What**: `fetch_or_create_index_key` reads the whole `{path}/index_keys` secret with `.unwrap_or_default()`:

```rust
let mut keys: HashMap<String, String> =
    vaultrs::kv2::read(&self.client, &self.config.mount, &path).await.unwrap_or_default();
```

Every failure mode collapses into "the secret is empty": a 5xx from Vault, a network blip, an expired or revoked token, a permission denial on that path, a malformed stored document. The function then takes the "first use of this name" branch — mints a new 32-byte key, inserts it into the now-empty map, and `kv2::set`s that one-entry map back over the real secret. The previously stored keys for every other column are gone.

**Why it matters**: This is unrecoverable silent data loss on the crypto path. The deterministic keys are, by the module's own doc comment, keys that "can never rotate without breaking determinism". Losing them means:

- every blind index already written no longer matches anything, so searchable-equality queries return zero rows for data that exists,
- every FPE-pseudonymised value stops detokenizing back to its plaintext,
- every HMAC token becomes uncorrelatable with the values that produced it.

Nothing surfaces the loss: `kv2::set` succeeds, the proxy logs `minted new deterministic index key` at info, and queries just come back empty. A transient Vault error during one cold start is enough. Compare the sibling `fetch_dek` (line 102), which propagates its read failure as `CoreError::UnknownKey` — the DEK path fails closed and this one fails open.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 kv2::read failure is propagated as an error rather than collapsed to an empty map; only a genuine not-found is treated as 'no keys stored yet'
- [x] #2 Minting a new index key never writes back a map missing entries that are present in the store
- [x] #3 A test covers both branches: read error -> index_key fails without writing; read not-found -> key is minted and stored
<!-- AC:END -->
