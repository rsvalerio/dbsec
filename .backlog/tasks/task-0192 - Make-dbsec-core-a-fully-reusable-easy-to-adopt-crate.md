---
id: TASK-0192
title: 'Make dbsec-core a fully reusable, easy-to-adopt crate'
status: To Do
assignee: []
created_date: '2026-08-19 16:58'
updated_date: '2026-08-20 18:34'
labels:
  - library
  - refactor
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Parent task for the library-first refactor recorded in plans/COMPARISON.md.

Goal: a Rust application that links dbsec-core gets the same protection the proxy gives — column-bound and row-bound encryption, blind-index search, FPE/token pseudonymization, masking, KMS-backed keys — at code time instead of at runtime, with minimal glue left to the caller and no dependency on the proxy crate.

Today the split runs the wrong way: ~2,800 LOC of library against ~19,600 LOC of proxy, with the KMS integration inside the binary crate and the PostgreSQL wire codec inside the library. Five things a library user cannot do without live in crates/proxy, and four of the five fail silently when reimplemented wrong.

No crypto behaviour changes in any child task: values written through the library and through the proxy must remain byte-identical envelopes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Every child task is Done
- [ ] #2 A plain sqlx application can encrypt, search and mask a column with no proxy process running, using only published crates
- [ ] #3 Values written by the library open through the proxy and vice versa, proven by a test
- [ ] #4 A plain sqlx application declares the policy once (derive + config) and gets encrypt/decrypt/search on its structs without calling seal/open per column (TASK-0192.08)
<!-- AC:END -->
