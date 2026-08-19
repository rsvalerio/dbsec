---
id: TASK-0188
title: >-
  ARCH: encrypt/mod.rs still carries a 1,600-line end-to-end test module after
  the layer split
status: Done
assignee: []
created_date: '2026-08-19 10:39'
updated_date: '2026-08-19 13:03'
labels:
  - code-review-rust
  - architecture
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/mod.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/mod.rs:540`

**What**: TASK-0160 moved the implementation into `frame`, `statement`, `query`,
`predicate`, `seal` and `lexer`, and moved the catalog/scope/seal/settings tests into
those files. What is left in `mod.rs` is 539 implementation lines plus a
`pub(in crate::encrypt) mod tests` of roughly 1,600 lines: the shared helpers
(`rewriter`, `catalog`, `query_frame`, `rewritten_query`, `refusal`, ...) and the
end-to-end suite that drives `QueryRewriter` through whole frames — extended-protocol
parameter binding, COPY classification, subquery and derived-table traversal, refusal
plumbing, the logging audit.

Those tests are genuinely cross-layer, so they were deliberately not pushed into
`frame.rs`/`statement.rs`/`query.rs`/`predicate.rs` during the wave. But the helper block
and the suite are two different things sharing one file, and the suite is now the largest
thing in `encrypt/`.

**Why it matters**: the file is still ~2,100 lines, which is the same "open a huge file to
find the test for a small module" cost TASK-0160 set out to remove — just moved from the
implementation side to the test side. Splitting the helpers into their own
`#[cfg(test)] mod test_support` and filing each end-to-end test under the layer it enters
through would finish the job.

**Origin**: discovered during TASK-0180 while fixing TASK-0160.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The shared test helpers live in their own module rather than alongside the suite
- [x] #2 Each end-to-end test sits in the module whose entry point it drives, or in a named integration test module
<!-- AC:END -->
