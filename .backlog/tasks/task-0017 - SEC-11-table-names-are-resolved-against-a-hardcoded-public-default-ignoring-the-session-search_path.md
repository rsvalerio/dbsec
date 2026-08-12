---
id: TASK-0017
title: >-
  SEC-11: table names are resolved against a hardcoded 'public' default,
  ignoring the session search_path
status: To Do
assignee:
  - TASK-0049
created_date: '2026-08-11 19:14'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - security
  - encrypt-path
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:45-53`

**What**: `WriteCatalog::table` resolves an unqualified SQL table name by defaulting the schema to `public`:

```rust
let schema = parts.next().map_or_else(|| "public".to_owned(), normalize);
```

The doc comment flags it ("search_path is not consulted — a caveat"), but the consequence is not only the missed-encryption direction that [[task-0001]] covers. There are two failure modes and they point opposite ways:

1. **Under-protection** — a client with `search_path = myschema` writing `INSERT INTO users …` targets `myschema.users`. If `public.users` is the configured protected table, the write does not match the catalog and the plaintext lands unencrypted. This is one more entry in the [[task-0001]] passthrough list.
2. **Mis-protection** — the configuration protects `myschema.users` and a client with `search_path = public` writes `INSERT INTO users …`. The catalog lookup for `(public, users)` misses, so nothing happens. But invert it: configure `public.users` while the client's `search_path` points at `myschema`, and a bare `users` reference is *encrypted for the wrong table*. The value is sealed and written into `myschema.users`, a table the read path never resolves (`resolve.rs` maps by the configured schema's OID), so it comes back as raw ciphertext forever. That is silent data corruption, not a missed encryption.

The read path is immune — it matches on `(table_oid, attnum)` resolved at startup, which is exact. The asymmetry is the point: the two paths disagree about what "users" means, and only the write path can be wrong.

**Why it matters**: `search_path` is not exotic — it is how multi-tenant schemas, `pg_bouncer` pools with `SET search_path`, and most schema-per-customer designs work, and drivers set it in connection options. The proxy cannot see it today because it never inspects `SET search_path` or the startup packet's `options` parameter. At minimum this needs to be a documented, enforced restriction (refuse to start when a protected table is not in `public`, or reject sessions that change `search_path`) rather than a comment in a private function.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The search_path assumption is stated in the crate/module docs and in the operator-facing config documentation, not only in a private fn comment
- [ ] #2 Either the proxy tracks search_path (startup options plus SET statements) when resolving unqualified names, or it enforces the assumption — e.g. refusing sessions that change search_path when protected tables are configured
- [ ] #3 The mis-protection direction (a bare name sealed for the wrong schema's table) is covered by a test
<!-- AC:END -->
