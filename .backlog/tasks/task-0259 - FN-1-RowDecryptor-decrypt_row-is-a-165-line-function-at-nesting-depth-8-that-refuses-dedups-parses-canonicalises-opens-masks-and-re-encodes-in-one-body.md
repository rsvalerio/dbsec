---
id: TASK-0259
title: >-
  FN-1: RowDecryptor::decrypt_row is a 165-line function at nesting depth 8 that
  refuses, dedups, parses, canonicalises, opens, masks and re-encodes in one
  body
status: Triage
assignee: []
created_date: '2026-08-22 00:38'
labels:
  - code-review-rust
  - function
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:850`

**What**: `decrypt_row` (crates/proxy/src/rows.rs:850-1014) runs 165 lines and mixes at least six abstraction levels: the up-front Ambiguous/TypeChanged refusal loop (861-881), the `repeated` fold (888-897), DataRow parsing into Cows (898-899), row-key canonicalisation (923-926), the per-position open/attribute/mask block (927-990) and the projected-size/frame bound bookkeeping (991-1008). The open step alone is a `for` → `let` → block → `match` → arm → `match (at, ...)` → arm → `match transform.open` → `Err(RowKeyMissing) => return Err(row_keys[at].why.take().expect(..))` chain, eight levels deep (rows.rs:956-981). `inspect` (600-667) and `check_for_stale_mapping` (750-826) are 67 and 76 lines respectively; the latter runs the same `named_like_protected` closure twice over every field for two separate `find`s (784, 803).

**Why it matters**: This is the hottest and most security-critical function on the read path (every DataRow of every protected result set passes through it), and its correctness argument — which arm refuses, which attributes, which takes `why` exactly once — is spread over nested matches the reader has to hold in their head. A future change to the row-key handling (the area that has produced TASK-0153/0165/0185) has to be made inside this pyramid.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `decrypt_row` is split into named helpers at one abstraction level each, e.g. `refuse_description_level(positions)`, `open_position(...) -> Result<Option<Vec<u8>>, Error>`, and a `RowRewrite { values, projected, changed }` that owns the bound check and the Cow swap
- [ ] #2 No function in rows.rs exceeds ~60 lines or brace depth 5 (state-machine `match` in `inspect` may stay as is)
- [ ] #3 `check_for_stale_mapping` classifies each field once (computed / suspect / fine) in a single pass instead of two `find`s over the same closure
- [ ] #4 Existing rows.rs tests pass unchanged
<!-- AC:END -->
