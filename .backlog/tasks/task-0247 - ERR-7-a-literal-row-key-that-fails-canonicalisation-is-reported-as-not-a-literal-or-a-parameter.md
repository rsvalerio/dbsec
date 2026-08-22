---
id: TASK-0247
title: >-
  ERR-7: a literal row key that fails canonicalisation is reported as 'not a
  literal or a parameter'
status: Triage
assignee: []
created_date: '2026-08-21 19:54'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/seal.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/seal.rs:328`

**What**:
```rust
rowkey::canonical(spec.type_oid, rowkey::Format::Text, Some(&text)).ok().map(RowKeySource::Literal)
```
`row_key_source` discards the `RowKeyType` reason with `.ok()`, so `INSERT INTO users (id, ssn) VALUES ('abc', '...')` on an integer row key reaches `rewrite_insert_values` (seal.rs:393-399) / `conflict_row` (seal.rs:240) as `None` and is reported through `Unprotected::RowKeyMissing` with shape "INSERT whose row key is not a literal or a parameter" — which it plainly is. The Bind-time sibling `bind_row_key` (frame.rs:99-104) keeps and reports the `why`.

**Why it matters**: under `reject` the operator and client are told to fix the wrong thing; under `warn` the value seals cell-only with a misleading log line.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 row_key_source returns a type that carries the RowKeyType reason, and the literal case surfaces it in the refusal/warn text the way bind_row_key does
- [ ] #2 A test writes a non-canonicalisable literal row key and asserts the message names the canonicalisation failure rather than 'not a literal or a parameter'
<!-- AC:END -->
