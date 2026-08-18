---
id: TASK-0141
title: code-review-plan-wave24
status: Done
assignee:
  - code-review-wave
created_date: '2026-08-18 09:59'
updated_date: '2026-08-18 19:52'
labels:
  - code-review-wave
dependencies:
  - TASK-0127
  - TASK-0133
modified_files:
  - crates/core/src/envelope.rs
  - crates/proxy/src/columns.rs
  - crates/proxy/src/rows.rs
  - Cargo.toml
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Crypto: row binding and key-material remnants
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0143 wave26 (crates/proxy/src/rows.rs)

Branch: code-review/TASK-0141

PARKED (merged, not closed). One commit landed on main by fast-forward: 5d29159
`docs(crypto): argue the unbound row half and the unwiped GHASH subkey in place`.

Members:
- TASK-0133 — Done. AC #1 satisfied via its second branch (record the decision). The
  decision turned out not to be the cost/benefit call the task assumed: verified against
  ghash 0.5.1 / polyval 0.6.2, enabling those features would not wipe H on any platform
  dbsec ships on, because `polyval::autodetect::Polyval` stores its backend in a `union`
  of `ManuallyDrop` whose destructors never run (and the aarch64 `pmull` backend has no
  zeroize `Drop` at all). Recorded next to the `aes` entry in the workspace Cargo.toml
  and in the envelope module docs.
- TASK-0127 — NOT Done, stays In Progress. AC #2 satisfied via its second branch (the
  design note now exists at plans/PLAN.md, "Why the row half is not bound"). AC #1 is not
  implementable at this layer and no format change was made.

Why TASK-0127 could not be closed: relocation detection requires the opener to know where
the bytes belong independently of the bytes, so any identifier riding inside the envelope
is copied with it. The identity must be the row's primary key, supplied from outside, and
neither path can get it without deployment rules the proxy cannot impose — client-generated
keys only on protected tables (a `serial` key does not exist when the write path rewrites
the statement), single-row UPDATEs (one bound parameter cannot become a different
ciphertext per target row), and every read projecting its table's key in a type the proxy
can canonicalise (RowDescription's type OID and format code are currently discarded, so
`id = 42` differs between text and binary clients). Full analysis and the one viable
design ("declared row key", `DBS3`) are on TASK-0127 and in PLAN.md. Adopting it is a
product decision, not a code-review fix, which is why this wave parks rather than forcing
a second stored-format change.

Pre-merge `ops verify`: clean (7/7). Pre-merge `cargo test --workspace --all-features`:
clean, 312 passed / 0 failed, including all 16 `crates/core/tests/props.rs` properties.
Integration `ops verify`: clean (7/7). Integration test suite: clean, same counts. `main`
had not moved, so the rebase was a no-op and no conflicts arose.

The worktree ../.wave-TASK-0141 and branch code-review/TASK-0141 are left in place per the
parked-wave rule; both are clean and fully merged into main.

Closed once TASK-0127 was implemented on feat/task-0127-row-binding. The wave correctly parked rather than forcing a format change it could not complete; the design it wrote up (declared row key + DBS3) is what shipped.
<!-- SECTION:NOTES:END -->
