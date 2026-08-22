---
id: TASK-0276
title: >-
  SEC-31: a derived table's column-alias list `(SELECT email FROM users) s(e)`
  is ignored, so `s.e = '…'` resolves to nothing and is relayed silently
status: Triage
assignee: []
created_date: '2026-08-22 00:45'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/query.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/query.rs:289`

**What**: derived_scope (query.rs:289-349) names the carried columns from the inner projection (`email`, or the SELECT-item alias) and uses only `alias.name` (query.rs:343-346); `TableAlias::columns` — the SQL-standard column renaming `FROM (SELECT email FROM users) AS s(e)` — is never consulted. The outer `WHERE s.e = 'a@x'` then resolves via TableScope::resolve to Unknown: no rewrite, and protected_operand/ambiguous_operand find nothing, so no Unprotected site. The same alias list also renames columns for the read-direction check (computed_protected_column), so `SELECT lower(e) FROM (SELECT body FROM notes) s(e)` raises no ComputedColumn either.

**Why it matters**: Plaintext compared against the stored form matches no rows with no signal, and a mask-only column reached through a renamed derived column leaves unmasked — the two outcomes the scope layer exists to prevent, reachable through ordinary standard SQL.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 derived_scope applies `alias.columns` positionally over the carried projection, renaming both the write and read column sets (and bailing to a conservative 'unknown' report if the alias list length does not match the projection)
- [ ] #2 Tests: `s(e)` renaming over a searchable column is rewritten; over a mask-only column, `lower(e)` raises ComputedColumn
<!-- AC:END -->
