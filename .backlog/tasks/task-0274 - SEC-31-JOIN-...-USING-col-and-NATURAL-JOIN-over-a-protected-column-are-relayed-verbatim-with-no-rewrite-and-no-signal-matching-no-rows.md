---
id: TASK-0274
title: >-
  SEC-31: JOIN ... USING (col) and NATURAL JOIN over a protected column are
  relayed verbatim with no rewrite and no signal, matching no rows
status: Triage
assignee: []
created_date: '2026-08-22 00:45'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/query.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/query.rs:499`

**What**: join_condition (query.rs:480-501) returns None for JoinConstraint::Using and JoinConstraint::Natural, so rewrite_join_conditions (query.rs:175) and select_expressions never see them, and nothing else inspects the USING column list against the scope. `SELECT * FROM users JOIN profiles USING (email)` — or a NATURAL JOIN between two tables sharing a protected column name — compares the stored forms (two independently sealed envelopes, or a plaintext against a sealed form when only one side is protected). The equivalent `ON users.email = profiles.email` is signalled as Unprotected::Predicate (column-reference operand), so the USING spelling is strictly less protected than the ON spelling.

**Why it matters**: Sealed values differ per row even for equal plaintexts, so the join yields zero rows silently; a LEFT JOIN USING yields NULLs for every row. `reject` does not refuse it because no Unprotected site is raised, so fail-closed mode is blind to it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 rewrite_join_conditions resolves every ident in JoinConstraint::Using against the scope and raises Unprotected::Predicate / UnindexedPredicate (shape 'JOIN USING') when it names a protected column; NATURAL JOIN raises a site when any protected column name is shared by the joined relations in scope
- [ ] #2 Tests: USING over a searchable column, USING over a non-searchable protected column, NATURAL JOIN over two protected tables — refused under reject, warned under warn
<!-- AC:END -->
