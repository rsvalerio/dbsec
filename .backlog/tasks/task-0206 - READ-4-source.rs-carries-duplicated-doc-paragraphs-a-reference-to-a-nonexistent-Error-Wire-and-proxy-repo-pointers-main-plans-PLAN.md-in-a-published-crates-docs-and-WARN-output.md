---
id: TASK-0206
title: >-
  READ-4: source.rs carries duplicated doc paragraphs, a reference to a
  nonexistent Error::Wire, and proxy-repo pointers (main, plans/PLAN.md) in a
  published crate's docs and WARN output
status: Triage
assignee: []
created_date: '2026-08-21 19:36'
labels:
  - code-review-rust
  - readability
dependencies: []
modified_files:
  - crates/vault/src/source.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/vault/src/source.rs:218` (also `crates/vault/src/source.rs:291`, `crates/vault/src/source.rs:801`, `crates/vault/src/source.rs:72`, `crates/vault/src/source.rs:657`, `crates/vault/src/source.rs:29`, `crates/vault/src/source.rs:65`)

**What**:
- `KeyStore` (218-223) and `VaultStore` (291-292) each have two consecutive, overlapping doc paragraphs saying the same thing — a leftover from the extraction out of the proxy.
- `decode_key_b64`'s doc (801-804) says `connect` converts the error "through `Error::Wire`" — no such variant exists in this crate (`connect` returns `Error::Key` via `#[from]`).
- The module doc (72) says the multi-thread runtime is required "(`main` builds one)" and (29, 65) points at `plans/PLAN.md` for rotation and revocation procedures; the shared-map migration WARN (657-662) tells the operator to see "the procedure in plans/PLAN.md". `dbsec-vault` is published to crates.io with `documentation = docs.rs`; a downstream user has no `main`, no `plans/PLAN.md`, and the log line sends them to a file in a repository they may not have.

**Why it matters**: Docs that reference things that do not exist (READ-4/READ-5) erode trust in the rest of the docs, and an operator-facing WARN whose only remediation pointer is unreachable turns a documented procedure into a dead end for every non-monorepo user.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Duplicate doc paragraphs on KeyStore and VaultStore are collapsed to one each
- [ ] #2 decode_key_b64's doc describes the actual conversion (Error::Key) and no doc in the crate names a nonexistent variant
- [ ] #3 Crate docs and the migration WARN describe the runtime requirement and the shared-map retirement procedure in-crate (or link to a published URL), with no reference to the proxy's main or plans/PLAN.md
<!-- AC:END -->
