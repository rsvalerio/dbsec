---
id: TASK-0127
title: >-
  Envelope AAD binds the column but not the row, so a value can still be
  relocated between rows of the same column
status: Triage
assignee: []
created_date: '2026-08-17 20:22'
labels:
  - code-review-rust
  - security
  - crypto
dependencies: []
modified_files:
  - crates/core/src/envelope.rs
  - crates/proxy/src/columns.rs
  - crates/proxy/src/rows.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/envelope.rs:59` (`CellContext`), `crates/proxy/src/columns.rs:60` (what is bound), `crates/proxy/src/rows.rs:391` (read path, which has no row identity)

**What**: TASK-0082 bound `schema.table.column` into the GCM associated data, so a ciphertext pasted into a *different column or table* now fails authentication. The row half of that finding is not covered: copying a stored blob from one row's `users.ssn` into another row's `users.ssn` still decrypts cleanly, because both cells share the same context string.

Row binding was not implemented because neither data path knows a row's identity. The write path rewrites INSERT/UPDATE parameters before the server assigns generated keys, so the primary key of the row being written is frequently not in the statement at all; the read path matches result columns by `(table oid, attnum)` and never sees a primary key unless the client happened to select it. Closing this needs a design decision above the envelope — requiring a configured row key present in every protected statement, or an opaque per-row token the proxy maintains — not a change to `CellContext`.

**Why it matters**: the headline scenario in TASK-0082 — an attacker with write access to stored bytes copying a high-privilege user's `users.ssn` into their own row and reading it back through the proxy — is a cross-*row* relocation, and it is still undetected. Cross-column and cross-table relocation are now caught, so this is the remaining half of the original confidentiality break.

**Origin**: discovered during TASK-0118 while fixing TASK-0082 (the row half of its AC #2 was left unsatisfiable at this layer). The limitation is documented in `plans/PLAN.md` (Caveats) and in the `envelope` module docs so it is not mistaken for coverage.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A ciphertext moved into the same column of a different row fails authentication on read
- [ ] #2 The chosen row identity is available on both the write and the read path, or the design note records why the deployment must supply it
<!-- AC:END -->
