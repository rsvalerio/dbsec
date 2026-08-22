---
id: TASK-0228
title: >-
  SEC-11: index_key_path validates the KV path segment with a four-item
  denylist, so a column name carrying ?, #, %, whitespace or control characters
  is interpolated into the request URL unchecked
status: Triage
assignee: []
created_date: '2026-08-21 19:50'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/vault/src/source.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
<!-- scan confidence: candidates to inspect -->

**File**: `crates/vault/src/source.rs:304`

**What**: `index_key_path` rejects only `""`, `"/"`-containing, `"."` and `".."` and then does `format!("{}/index_keys/{}", self.config.path, name)`; `vaultrs`/`rustify` interpolate that string into the request URL. A `name` such as `public.users.email?version=1`, `a#b`, `a%2Fb` or one with a space or a newline is not refused here and would either be percent-encoded by the URL builder (best case: a secret stored under a surprising encoded name that `vault kv get` cannot easily address) or reinterpreted as a query/fragment (worst case: a different secret path). Names come from the policy file, so the doc comment correctly calls this "a surprising configuration, not an attack" — but the policy file is where an operator types, and a typo should be a clean refusal naming the rule, not a secret created at a path nobody can find again. `config.path` and `config.mount` are interpolated with no validation at all. Verify how `rustify` builds the URL for the locked `vaultrs` version before deciding the severity; the fix is the same either way.

**Why it matters**: SEC-11 — validate at the boundary with an allowlist, not a denylist: the set of characters a KV v2 path segment should contain for this crate is `[A-Za-z0-9._-]`, which every `schema.table.column` name satisfies. An index key that lands under an encoded or truncated path is one that can never be rotated or audited by hand, and deterministic keys are the ones the module docs say must never be lost.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 index_key_path accepts only an explicit allowlist of path-safe characters (documented on the function) and its refusal names the offending name
- [ ] #2 VaultConfig::resolve (or connect) validates mount, path and transit_mount/transit_key the same way so a bad value is a startup error
- [ ] #3 Tests cover accepted names (schema.table.column), and rejected names with /, ?, #, %, whitespace, empty, . and ..
<!-- AC:END -->
