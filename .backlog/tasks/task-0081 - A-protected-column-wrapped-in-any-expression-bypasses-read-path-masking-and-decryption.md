---
id: TASK-0081
title: >-
  A protected column wrapped in any expression bypasses read-path masking and
  decryption
status: Triage
assignee: []
created_date: '2026-08-14 14:06'
labels:
  - security-review
  - security
  - read-path
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:238-247` (position matching), `:317-322` (`check_for_stale_mapping`)

**What**: the read path decides which `DataRow` positions to decrypt/mask by matching each `RowDescription` field on `(table_oid, attnum)`. PostgreSQL populates those only for a *direct* base-table column reference; any cast, function, string op, or subquery-derived output column arrives as `table_oid = 0, attnum = 0` and matches nothing, so it is relayed untouched. The stale-mapping safety net cannot catch it either — it is explicitly gated on `field.table_oid != 0` (the comment reads "so not a computed expression").

**Why it matters**: this bypasses the policy in *every* mode, including `on_unprotected = "reject"`, and needs only ordinary query access.
- Mask-only column (`transform = "none"`, `mask = ...`, plaintext at rest): `SELECT ccnum || '' FROM cards` returns the **full unmasked value** — a direct disclosure of exactly what the mask hides.
- Encrypted column: `SELECT email::text FROM users` hands back raw `blind_index || envelope` ciphertext with no error — the silent stored-form passthrough the refusal machinery exists to prevent.
Triggers: `email || ''`, `email::text`, `COALESCE(email,'')`, `SELECT email FROM (SELECT email FROM users) s`. Verified against source.

**Fix shape**: treat any `RowDescription` field whose *name* matches a configured protected column as suspect regardless of OID (request a re-resolution / refuse under `reject`), or otherwise close the "computed column over a protected name" gap so it cannot silently relay the stored form.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A computed/cast/subquery output over a mask-only column no longer returns the value in the clear
- [ ] #2 A computed output over an encrypted column is refused or decrypted, never relayed as stored ciphertext
- [ ] #3 A test drives an expression-wrapped protected column through the read path in both warn and reject modes
<!-- AC:END -->
