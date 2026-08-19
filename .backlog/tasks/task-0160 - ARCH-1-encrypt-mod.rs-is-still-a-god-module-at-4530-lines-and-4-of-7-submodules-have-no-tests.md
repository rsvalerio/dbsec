---
id: TASK-0160
title: >-
  ARCH-1: encrypt/mod.rs is still a god module at 4,530 lines, and 4 of 7
  submodules have no tests
status: Done
assignee:
  - TASK-0180
created_date: '2026-08-19 08:30'
updated_date: '2026-08-19 10:39'
labels:
  - code-review-rust
  - architecture
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/mod.rs
  - crates/proxy/src/encrypt/seal.rs
  - crates/proxy/src/encrypt/scope.rs
  - crates/proxy/src/encrypt/catalog.rs
  - crates/proxy/src/encrypt/settings.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/mod.rs:1`

**What**: after both split commits `mod.rs` holds 1,988 implementation lines plus a 2,541-line
test module. Its concerns are still: pgwire frame dispatch (`on_frame`, `bind`), statement
dispatch, predicate traversal, the `unprotected` policy gate, the tokenize/parse layer, and
value sealing (`seal_expr`, `bytea_literal`).

The split's stated payoff — "tests moved with the code they cover" — landed for only 3 of 7
modules. `catalog.rs`, `scope.rs`, `seal.rs` and `settings.rs` have **no** `#[cfg(test)]`
module; 86 of 97 tests are still in `mod.rs`.

**Why it matters**: the 500-line threshold is exceeded 9x, and the cost is now concentrated in
the test block: changing `settings.rs`'s token scan means opening a 4,530-line file to find its
tests. `seal.rs`'s own doc claims it contains "the single choke point where a plaintext becomes
a stored form" — that is `seal_expr`, still at `mod.rs:1671`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 mod.rs implementation drops below ~800 lines: the frame layer moves to its own module and seal_expr moves to seal.rs so its doc becomes true
- [x] #2 Predicate traversal moves to a predicate module
- [x] #3 Tests for catalog, scope, seal and settings move into those files, matching array/lexer/unprotected
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
encrypt/mod.rs implementation is now 539 lines (was 1,988): it keeps only QueryRewriter and its state, the catalog lookups, the Unprotected decision point and the small value-sealing types, plus a new "Module layout" doc table. Four new modules: frame.rs (pgwire frame dispatch: on_frame, bind, discard_until_sync, ready_for_query, describe_target, record_param, bind_row_key, encode_param), statement.rs (rewrite_sql and the per-statement-kind arms), query.rs (scope building and query traversal), predicate.rs (AC#2: predicate traversal and the searchable rewrite). seal_expr, bytea_literal and literal_plaintext moved to seal.rs, so its doc claim about the single choke point is now true; tokenize/parse_tokens/parse_sql moved to lexer.rs. AC#3: 49 tests moved out of mod.rs into settings.rs (17), seal.rs (17), scope.rs (13) and catalog.rs (2); mod.rs tests became pub(in crate::encrypt) so the shared helpers are reachable, matching the array.rs precedent. Test count unchanged (295 proxy tests pass). cargo doc stays warning-free under the new broken_intra_doc_links = deny.
<!-- SECTION:NOTES:END -->
