---
id: TASK-0275
title: >-
  SEC-31: join ON constraints in UPDATE ... FROM, DELETE ... USING and
  parenthesised joins are swept by rewrite_selection only, so a subquery inside
  them is never walked
status: Triage
assignee: []
created_date: '2026-08-22 00:45'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/query.rs
  - crates/proxy/src/encrypt/statement.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/query.rs:187`

**What**: rewrite_predicate's doc (predicate.rs:36-44) says keeping rewrite_selection and rewrite_nested_queries behind one call is what stops a site getting only one half. rewrite_join_conditions (query.rs:187) calls rewrite_selection alone. rewrite_select compensates via select_expressions (query.rs:509-512), but that only enumerates top-level `table.joins` — constraints inside TableFactor::NestedJoin are not included — and rewrite_update (statement.rs:198) / rewrite_delete (statement.rs:240) call rewrite_join_conditions with no nested sweep at all. So `UPDATE t SET x = 1 FROM a JOIN b ON b.id IN (SELECT id FROM users WHERE email = 'a@x')` and `SELECT ... FROM (a JOIN b ON b.id = (SELECT id FROM users WHERE email = $1))` leave the inner searchable equality unrewritten; rewrite_selection's InSubquery/Eq arm only inspects the outer operand `b.id`, which is unprotected, so nothing is signalled.

**Why it matters**: The nested predicate compares plaintext against the stored form and matches nothing, silently; under reject nothing is refused. This is the same class the rewrite_predicate doc calls out, reintroduced at the join-constraint site.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 rewrite_join_conditions calls rewrite_predicate (both halves) for each ON constraint, and the join_constraints entry is removed from select_expressions so no constraint is walked twice
- [ ] #2 Tests: subquery with a searchable equality inside an ON clause of UPDATE ... FROM, DELETE ... USING and a parenthesised join in SELECT, asserting the index rewrite
<!-- AC:END -->
