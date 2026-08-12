---
id: TASK-0038
title: >-
  SEC-15: placeholder_index underflows on $0, panicking in debug and rewriting
  the column against an unbindable parameter in release
status: To Do
assignee:
  - TASK-0050
created_date: '2026-08-11 19:35'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - security
  - correctness
  - encrypt-path
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:452-454`

**What**:

```rust
fn placeholder_index(placeholder: &str) -> Option<usize> {
    placeholder.strip_prefix('$').and_then(|n| n.parse::<usize>().ok()).map(|n| n - 1)
}
```

`n` comes from client-supplied SQL. `$0` parses to `0`, and `0usize - 1` is unchecked subtraction on a value the client chose. The workspace sets no `overflow-checks` override (root `Cargo.toml:51-53` sets only `lto` and `strip`), so the two profiles diverge:

- **debug** (`cargo test`, `cargo run`, any development or CI deployment): the subtraction panics. The panic unwinds out of `QueryRewriter::on_frame`, through `relay`'s transform closure, and aborts the session task — a remote panic reachable pre-authentication, since the client→upstream relay rewrites frames from the moment the startup message is forwarded.
- **release**: it wraps to `usize::MAX`. The entry is pushed into `ParamTransforms`, and at Bind `values.get_mut(usize::MAX)` returns `None`, so the parameter is never transformed. But `rewrite_equality` has already replaced the column with `substring(col from 1 for 32)` (`encrypt.rs:437`) and returned `true`, so the statement *is* rewritten: the query now compares a 32-byte index prefix against an untransformed parameter and matches nothing.

Both `rewrite_equality` (`encrypt.rs:426`) and `seal_expr` (`encrypt.rs:493`) call it, so both the search and the seal path are reachable. `$0` is not valid PostgreSQL, but the proxy parses the SQL before the server ever sees it, so the server's rejection comes too late.

**Why it matters**: This is untrusted input reaching unchecked arithmetic. The debug-profile panic is the sharper end — a one-line query kills the session, and nothing about the input is exotic enough to be caught by an operator's mental model of "malformed SQL". The release behaviour is quieter but worse in kind: a silently wrong rewrite that returns no rows, which is the same fail-open shape as [[task-0037]]. Note the neighbouring `.parse::<usize>().ok()` already handles the "not a number" case correctly by returning `None` — the zero case simply was not considered, and the fix is the same shape: `n.checked_sub(1)`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 placeholder_index returns None for $0 rather than underflowing — e.g. via checked_sub(1)
- [ ] #2 A parameter reference the rewriter cannot resolve leaves the surrounding expression untouched; the column is not rewritten to an index prefix when the matching parameter action was not recorded
- [ ] #3 A test sends WHERE email = $0 and INSERT ... VALUES ($0) through on_frame and asserts no panic and no partial rewrite, and it passes under a debug profile
- [ ] #4 Other arithmetic on client-supplied protocol values in the encrypt path is audited for the same pattern
<!-- AC:END -->
