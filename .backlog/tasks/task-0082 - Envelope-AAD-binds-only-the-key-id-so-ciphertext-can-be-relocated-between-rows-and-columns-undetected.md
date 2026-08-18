---
id: TASK-0082
title: >-
  Envelope AAD binds only the key id, so ciphertext can be relocated between
  rows and columns undetected
status: In Progress
assignee:
  - TASK-0118
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:22'
labels:
  - security-review
  - security
  - crypto
dependencies: []
modified_files:
  - crates/core/src/envelope.rs
  - crates/proxy/src/columns.rs
  - crates/core/src/transform.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/envelope.rs:103` (encrypt AAD), `:123` (decrypt AAD); enabled by `crates/proxy/src/columns.rs:43` (one process-wide DEK) and `crates/core/src/transform.rs:109-122` (blind index split-and-discarded on read).

**What**: the only AEAD associated data is the 16-byte `key_id`, and every encrypted column shares one process-wide active DEK — hence one identical `key_id`. A ciphertext therefore carries no cryptographic binding to the table, column, or row it belongs to. The envelope doc's claim "a value cannot be replayed under another key id" is true but does not cover replay to another *location under the same key id*.

**Why it matters**: an attacker who can write stored bytes (malicious DBA, at-rest DB compromise, a direct DB connection, or SQL-injection `UPDATE`) can copy a `DBS1|key_id|nonce|ct+tag` blob from one cell into another — a high-privilege user's `users.ssn` into the attacker's own row, or swap `ssn` <-> `credit_card` between columns. On read-back the same `key_id` resolves, GCM authenticates, and the value decrypts cleanly with zero tamper signal. This is a confidentiality break (cross-row) and an integrity break (cross-column) squarely inside the product's at-rest threat model. The searchable blind index is not re-verified on read, so it does not help.

**Fix shape**: thread a per-cell context — `schema.table.column`, ideally plus a row/primary-key identifier — into the AAD on both seal and open. Needs a format/version bump and a migration story for existing ciphertexts.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Encrypt and decrypt bind a per-cell context (at least schema.table.column) into the AAD
- [ ] #2 A ciphertext moved to a different column or a different rows cell fails authentication on read
- [x] #3 The stored-format version is bumped and a migration path for existing envelopes is documented
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented in wave TASK-0118 (branch code-review/TASK-0118).

Done: the GCM associated data is now `key_id || schema.table.column` (`envelope::CellContext`), threaded from `columns::build` through `EncryptTransform` so both data paths reach the same binding for a column. Stored format bumped `DBS1` -> `DBS2`; `DBS1` is still read (AAD = key id alone) so an upgrade needs no migration to stay readable, and re-writing a `DBS2` header as `DBS1` fails authentication rather than downgrading. Migration procedure documented in plans/PLAN.md ("Upgrading DBS1 rows to the bound envelope") plus the envelope module docs, README and the PLAN caveats.

AC #1 and #3 satisfied. AC #2 is satisfied for the cross-column and cross-table half only: a value relocated into another column or table now fails authentication (covered by unit, integration-level and property tests). The cross-*row* half is NOT implemented — neither data path knows a row's identity (the write path rewrites parameters before generated keys exist; the read path matches result columns by (table oid, attnum) and never sees a primary key), so it needs a design above the envelope. Filed as TASK-0127 (Triage) and documented as a caveat rather than left implicit. Task stays In Progress for that reason.
<!-- SECTION:NOTES:END -->
