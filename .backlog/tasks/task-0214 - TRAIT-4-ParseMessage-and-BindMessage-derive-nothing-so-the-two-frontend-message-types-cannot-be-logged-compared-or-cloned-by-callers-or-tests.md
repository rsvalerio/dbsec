---
id: TASK-0214
title: >-
  TRAIT-4: ParseMessage and BindMessage derive nothing, so the two frontend
  message types cannot be logged, compared or cloned by callers or tests
status: Triage
assignee: []
created_date: '2026-08-21 19:48'
labels:
  - code-review-rust
  - api-design
dependencies: []
modified_files:
  - crates/pgwire/src/lib.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/pgwire/src/lib.rs:217-221` (`ParseMessage`), `:242-248` (`BindMessage`)

**What**: `RowField` and `Startup` carry `Debug, Clone, PartialEq, Eq` (and `Startup` is `Copy`), but the two public frontend message structs derive nothing at all. Every field is a `&[u8]`, `Vec<i16>` or `Vec<Option<&[u8]>>`, all of which are `Debug + Clone + PartialEq + Eq`, so the derives are free. The consequence shows in the crate's own tests: `bind_message_roundtrips` has to assert five fields one at a time instead of `assert_eq!(parsed, expected)`, and the fuzz target compares `params` and `param_formats` individually after re-parsing. Downstream, `dbsec-proxy` cannot `tracing::debug!(?bind)` a refused Bind or hold a `ParseMessage` in a struct that itself derives `Debug`.

**Why it matters**: Published-crate API surface. Missing derives on a public type are a breaking change to add only in the sense that nothing breaks, but their absence forces every consumer to hand-roll comparison and formatting, and the tests that exist are weaker for it (a new field added to `BindMessage` is not covered by any existing equality assertion). `RowField`, which carries only `&[u8]` and integers, could also be `Copy`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ParseMessage and BindMessage derive Debug, Clone, PartialEq, Eq
- [ ] #2 RowField additionally derives Copy, or a comment says why not
- [ ] #3 bind_message_roundtrips and parse_message_roundtrips compare whole messages with assert_eq! against a constructed expected value
<!-- AC:END -->
