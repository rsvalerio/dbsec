---
id: TASK-0086
title: >-
  UPDATE ... FROM and DELETE ... USING silently skip searchable predicates over
  the joined relation
status: Done
assignee:
  - TASK-0121
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:36'
labels:
  - security-review
  - security
  - sql-rewrite
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:523-534` (UPDATE arm), `:537-547` (DELETE arm), scope at `:749-765`.

**What**: the UPDATE arm destructures `Statement::Update { table, assignments, selection, .. }` — the `..` drops sqlparser's `Update.from` — and builds the predicate scope from the target table only. The DELETE arm uses only `delete.from` and ignores sqlparser's separate `Delete.using`. A searchable-column reference into the FROM/USING relation therefore resolves to nothing in scope, so `rewrite_selection` misses it and the predicate is relayed verbatim with **no rewrite and no Unprotected signal, in both warn and reject** — violating the module contract ("anything else that mentions a searchable column ... is an Unprotected site rather than a silent no-op").

**Why it matters** (`users.email` searchable): `DELETE FROM sessions USING users WHERE users.email = $1 AND sessions.user_id = users.id` compares plaintext against `blind_index||envelope` -> matches nothing -> silently deletes zero rows (a "revoke this user's sessions" that no-ops). The inverted `... WHERE users.email <> $1` keeps every row -> **deletes everything**. Security-relevant DML producing wrong results with no error. Verified against source.

**Fix shape**: include `Update.from` and `Delete.using` when building the predicate scope so their searchable columns are rewritten or gated like the primary relation's.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A searchable predicate over an UPDATE ... FROM or DELETE ... USING relation is rewritten to blind-index form
- [x] #2 If such a predicate cannot be rewritten it routes through the on_unprotected gate rather than relaying verbatim
- [x] #3 Tests cover DELETE ... USING with both equality and inequality over a searchable column
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in TASK-0121 (wave 16). The same walk gap applied to derived tables beside the target — UPDATE ... FROM (SELECT ...) and DELETE ... USING (SELECT ...) never descended into the subquery — so `rewrite_derived_tables` was extracted from `rewrite_select` and is now called from all three sites, with tests. The parenthesized-join variant of the same class is filed as TASK-0132.
<!-- SECTION:NOTES:END -->
