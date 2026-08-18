---
id: TASK-0135
title: >-
  A searchable predicate inside a COPY (query) TO STDOUT is never rewritten, so
  it silently matches no rows
status: Done
assignee:
  - TASK-0139
created_date: '2026-08-17 20:58'
updated_date: '2026-08-18 10:35'
labels:
  - code-review-rust
  - correctness
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:572` (the `Statement::Copy` arm in `rewrite_statement`)

**What**: the COPY arm classifies its source and returns `Ok(false)` — it never calls `rewrite_query`. A `COPY (SELECT id FROM users WHERE email = 'alice@example.com') TO STDOUT` therefore compares the client's plaintext against the stored `blind_index || envelope`, matching nothing, and no `Unprotected::Predicate` / `UnindexedPredicate` site is reached either.

**Why it matters**: this is the failure `rewrite_nested_queries` documents as the unsafe one — "no rows" is indistinguishable from "no such user", and an empty result feeding a `NOT IN` inverts the meaning of the query. TASK-0123 made the statement an `on_unprotected` site, so under `reject` it is now refused and under `warn` the operator is told the COPY is unprotected; but the warning is about the *leak*, not about the predicate, so under `warn` the empty result still arrives unexplained.

**Why it was not fixed there**: rewriting the query means the statement has to be re-rendered, and `COPY ... FROM STDIN` has no wire-valid rendering through sqlparser's `Display` (see `parse_sql`, which only parses it by appending a terminator). Any fix has to either render only the query source back into the original text range, or raise the predicate sites without rewriting — a decision worth making deliberately rather than inside the COPY classification change.

**Origin**: discovered during TASK-0123 while fixing TASK-0085.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A searchable predicate inside a COPY (query) TO STDOUT is either rewritten to an index match or reported as an Unprotected predicate site
- [x] #2 The fix does not re-render a COPY ... FROM STDIN into text the wire cannot carry
- [x] #3 A test drives COPY (SELECT ... WHERE searchable = 'literal') TO STDOUT in both modes
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0139. Decision on the re-rendering question: rewriting is safe and was applied. The COPY arm classifies the source first (so reject still refuses the leak before anything is rendered), then calls rewrite_query on the query source, gated on `to`. A query source only exists in the TO direction, so a statement marked changed here is never COPY ... FROM STDIN — the one shape with no wire-valid Display rendering. Everything else keeps its original source text via reassemble, and anything re-rendered is re-parsed and compared by render_validated. Verified empirically that every COPY (query) TO {STDOUT,PROGRAM,file} form, with modern and legacy options, round-trips through sqlparser 0.53 Display. Test: a_searchable_predicate_inside_a_copy_query_is_rewritten_or_reported (covers both modes, the unindexable-predicate site, and a COPY ... FROM STDIN relayed byte-for-byte beside a rewritten statement).
<!-- SECTION:NOTES:END -->
