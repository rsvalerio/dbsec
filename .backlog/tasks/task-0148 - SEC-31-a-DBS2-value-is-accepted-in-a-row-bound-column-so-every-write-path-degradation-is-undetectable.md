---
id: TASK-0148
title: >-
  SEC-31: a DBS2 value is accepted in a row-bound column, so every write-path
  degradation is undetectable
status: Done
assignee:
  - TASK-0178
created_date: '2026-08-19 08:27'
updated_date: '2026-08-19 09:39'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/core/src/envelope.rs
  - crates/core/src/transform.rs
  - crates/proxy/src/encrypt/unprotected.rs
  - crates/proxy/src/encrypt/mod.rs
  - README.md
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/envelope.rs:371`

**What**: `Cipher::decrypt` picks the AAD purely from the stored magic. A `DBS3` value with
no key errors, but a `DBS2` value opens under the cell-only AAD and the supplied
`binding.row` is silently discarded. There is no mode in which the opener asserts "this
column is configured row-bound, so a cell-only envelope here is a downgrade".

Combined with the write paths that fall back to `RowKeySource::None` — the `ON CONFLICT`
hole, an `UPDATE` whose `WHERE` does not pin the row, a negative-number row key literal — an
attacker who can get one cell-only value written into a row-bound column has a permanently
relocatable ciphertext under the current DEK.

The `RowKeyMissing` warning text compounds it: it says the value is "stored bound to no row
**and will not open**", which is untrue — it opens fine. The one operator-visible signal
describes a loud failure that never arrives, so the real, silent consequence goes
unlooked-for.

**Why it matters**: the binding is only as strong as its weakest write path, and nothing on
the read side re-establishes the policy. The module doc argues correctly that version
relabelling is not a downgrade; the actual downgrade vector is getting the *proxy* to write
the older version, which is unguarded and reachable through ordinary SQL.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 An opt-in strict mode makes a DBS2 envelope in a row-bound column an error, so back-compat is a stated migration window rather than a permanent hole
- [x] #2 The RowKeyMissing warning text is corrected: the value does open; what is lost is relocation detection
- [x] #3 A test seals with Binding::cell and asserts opening with Binding::row fails in strict mode
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Strict mode is opt-in per [[table]] (strict_row_binding, default false) and enforced on the read path: envelope::Binding gains a `strict` flag plus Binding::row_strict, and Cipher::decrypt returns the new Error::RowBindingDowngraded for a DBS2/DBS1 value in a row-bound column. EncryptTransform carries it via a .strict_row_binding(bool) builder wired from columns::build; rows::is_refusal treats it as a client-visible refusal. RowKeyMissing warn text corrected (the value does open; what is lost is relocation detection) and README documents the migration window.
<!-- SECTION:NOTES:END -->
