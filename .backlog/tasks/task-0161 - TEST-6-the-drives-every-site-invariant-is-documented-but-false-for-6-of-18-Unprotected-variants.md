---
id: TASK-0161
title: >-
  TEST-6: the 'drives every site' invariant is documented but false for 6 of 18
  Unprotected variants
status: Triage
assignee: []
created_date: '2026-08-19 08:31'
labels:
  - code-review-rust
  - test-coverage
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/mod.rs
  - crates/proxy/src/encrypt/unprotected.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/mod.rs:114`

**What**: the module doc states "Anything added later must stay inside that set;
`no_event_from_the_write_path_carries_a_plaintext_value` is the test that keeps it honest by
driving every site". Six variants are unreachable from that test:

- `RowKeyMissing` — the `rewriter()` helper passes `None` for `rows`, so `row_key_spec` always
  returns `None` and the site can never fire. Added in this range, never added to the list.
- `CopyQuery` — added in an earlier wave, likewise never added.
- `ComputedColumn` — no computed projection appears in the statement list.
- `UnindexedPredicate` — the fixture uses a searchable catalog, so predicates land on `Predicate`.
- `AmbiguousLiteral` — needs an ordinary `'...'` literal with a backslash after
  `standard_conforming_strings` goes off; the four backslash cases are all `E'...'` strings.
- `Copy { to: true }` — only the FROM STDIN direction is driven.

None leaks a value today; the problem is that nothing enforces it.

**Why it matters**: the logging contract is why `expr_shape` and `parser_error_kind` exist at
all. The doc names one test as the mechanical guard, and it silently stopped being one the
moment a variant was added without touching it — which has now happened twice in this range.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The test drives all 18 variants, including a row-bound fixture for RowKeyMissing and a COPY (SELECT) TO STDOUT for CopyQuery
- [ ] #2 Adding a variant without adding a driver fails the build — e.g. an exhaustive match over a constructed value of every variant inside the test
- [ ] #3 The module doc is accurate as written afterwards
<!-- AC:END -->
