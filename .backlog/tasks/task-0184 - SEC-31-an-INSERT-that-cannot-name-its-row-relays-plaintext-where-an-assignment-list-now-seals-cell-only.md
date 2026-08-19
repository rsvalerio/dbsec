---
id: TASK-0184
title: >-
  SEC-31: an INSERT that cannot name its row relays plaintext where an
  assignment list now seals cell-only
status: Done
assignee: []
created_date: '2026-08-19 09:43'
updated_date: '2026-08-19 12:24'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/seal.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/seal.rs:294` (`rewrite_insert_values`)

**What**: when a row-bound table's `INSERT` cannot name its row — the row key is absent
from the column list, or its value is neither a literal nor a parameter —
`rewrite_insert_values` reports `Unprotected::RowKeyMissing` and then
`return Ok(SealedValues::default())`. Under `on_unprotected = "warn"` that relays the
statement **unsealed**: the plaintext goes to the server in the clear.

TASK-0173 gave the assignment-list path (`QueryRewriter::row_of`) the opposite fallback:
report the site, then seal *cell-only* — the binding the table had before it declared a
row key. The two paths now disagree about what `warn` means for the same class of gap,
and the `INSERT` side is the weaker of the two.

**Why it matters**: `warn` exists so an unprotectable statement is still no worse than an
unconfigured one. Turning a relocatable ciphertext into plaintext at rest is a downgrade,
not a degradation, and it is the outcome the mode is meant to prevent. It also means
adopting `row_key` on a table can make its `INSERT`s *less* protected than before.

**Origin**: discovered during TASK-0173 while fixing TASK-0146.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 An INSERT into a row-bound table that cannot name its row seals cell-only under warn rather than relaying plaintext
- [x] #2 The refusal under reject is unchanged
- [x] #3 A test asserts the stored bytes of such an INSERT start with MAGIC (DBS2) under warn
<!-- AC:END -->
