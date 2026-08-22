---
id: TASK-0246
title: >-
  TEST-6: RowKeyRef::TypeChanged is produced and refused in rows.rs but never
  exercised by any test
status: Triage
assignee: []
created_date: '2026-08-21 19:54'
labels:
  - code-review-rust
  - testing
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:291` (producer), `crates/proxy/src/rows.rs:872` (refusal)

**What**: `if *type_oid != declared.type_oid { return RowKeyRef::TypeChanged { ... } }` and the `RowKeyRef::TypeChanged { .. } => Err(Error::Wire(dbsec_core::Error::RowKeyType(format!("{table}.{column} came back as type oid {wire} but resolved as type oid ...` arm have no test: grep for `TypeChanged` / "came back as type oid" across the 45 rows.rs tests, tests_e2e.rs and tests/ finds only the production lines. The sibling variants (`Ambiguous` at rows.rs:1840, `ProtectedValueTooLarge` at :2981/:3025) are tested.

**Why it matters**: this SEC-11 refusal — an `ALTER COLUMN ... TYPE` on the row key making read and write paths derive different keys — is the one with no coverage, so a regression that falls through to `Slot` (opening against a mis-canonicalised key and surfacing as a false tamper alarm) would not be caught.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A rows.rs test describes a row-keyed table whose key field carries a type_oid different from the resolved one and asserts decrypt_row returns Error::Wire(RowKeyType(_)) naming both OIDs and that is_refusal is true
- [ ] #2 A test asserts a matching type_oid still yields RowKeyRef::Slot
<!-- AC:END -->
