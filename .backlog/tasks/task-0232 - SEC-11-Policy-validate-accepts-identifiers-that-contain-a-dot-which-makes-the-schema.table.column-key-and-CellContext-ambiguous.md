---
id: TASK-0232
title: >-
  SEC-11: Policy::validate accepts identifiers that contain a dot, which makes
  the schema.table.column key and CellContext ambiguous
status: Triage
assignee: []
created_date: '2026-08-21 19:50'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/core/src/policy.rs
  - crates/core/src/protector.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/policy.rs:47-52` (also `crates/core/src/policy.rs:152-155`, `crates/core/src/policy.rs:458-477`, `crates/core/src/protector.rs:207-217`)

**What**: `split_table` splits `table` on its *first* dot and `qualified_name` joins `schema`, `table` and `column` with dots; `check_identifiers` bounds the length and warns on case folding but never refuses a `.` inside an identifier. PostgreSQL accepts quoted identifiers containing dots (`"acme.users"`, `"a.b"`), so a policy entry `table = "acme.users"` meant as the bare table `acme.users` in `public` is silently read as schema `acme`, table `users`, and a column `"b.c"` on table `a` produces the same `public.a.b.c` string as column `c` on table `a.b`. That string is both the deterministic key name and the `CellContext` bound into every envelope's AAD, so two distinct cells can share a key and a context — the cross-column relocation protection the crate is built around then does not apply between them. `Protector::lookup` has the same problem from the other side: it counts dots to decide whether a name is `table.column` or `schema.table.column`, so a caller cannot address any column whose identifiers contain a dot at all.

**Why it matters**: Low likelihood, but the failure is silent and lands exactly in the property the AAD is meant to guarantee. The `schema.table.column` convention is declared part of the stable stored format (lib.rs Compatibility), so the cheap fix is to refuse dots in identifiers at `validate` time (and in `TablePolicy::row_key`), where a refusal names the column and happens at startup.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Policy::validate returns Error::Policy for any schema, table, column or row_key identifier containing a '.' (and the refusal names the entry)
- [ ] #2 A test covers a dotted table name, a dotted column name and a dotted row_key
- [ ] #3 The policy module docs state that dotted identifiers are unsupported and why
<!-- AC:END -->
