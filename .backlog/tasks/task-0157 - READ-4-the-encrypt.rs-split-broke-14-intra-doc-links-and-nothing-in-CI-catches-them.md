---
id: TASK-0157
title: >-
  READ-4: the encrypt.rs split broke 14 intra-doc links, and nothing in CI
  catches them
status: Done
assignee:
  - TASK-0180
created_date: '2026-08-19 08:29'
updated_date: '2026-08-19 10:15'
labels:
  - code-review-rust
  - readability
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/mod.rs
  - crates/proxy/src/encrypt/array.rs
  - crates/proxy/src/encrypt/catalog.rs
  - crates/proxy/src/encrypt/scope.rs
  - crates/proxy/src/encrypt/settings.rs
  - crates/proxy/src/encrypt/unprotected.rs
  - crates/proxy/src/main.rs
  - crates/proxy/src/portal.rs
  - crates/core/src/keys.rs
  - Cargo.toml
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/mod.rs:94`

**What**: `cargo doc --no-deps --document-private-items` emits 14 `unresolved link` warnings,
all inside `crates/proxy/src/encrypt/`, each naming an item that lived in the same module
before the split and now sits in a sibling: `render_validated`, `parser_error_kind`,
`Unprotected::Predicate`, `Unprotected::Unparseable`, `tokenize`,
`WriteCatalog::protects_reads`, `bytea_literal`, `QueryRewriter::table`,
`QueryRewriter::unprotected`, `QueryRewriter::rewrite_nested_queries`, `WriteCatalog::new`,
`QueryRewriter::seal_expr`, `Unprotected`. All targets still exist; only the paths are missing.

Also present outside `encrypt/`: `main.rs:161` -> `config::describe_parse_error`,
`portal.rs:277` -> `Self::copy_data`, `keys.rs:26` -> `Deref`.

**Why it matters**: these modules carry the reasoning about *why* a site is or is not an
`Unprotected` hole, and the cross-references are how a reviewer navigates from one half of that
argument to the other. Nothing in CI runs `cargo doc`, so the breakage is invisible and
accumulates on every future move.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 cargo doc --no-deps --document-private-items emits zero unresolved-link warnings for the workspace
- [x] #2 Each link is fixed with a real path, not by unlinking the text
- [x] #3 rustdoc::broken_intra_doc_links = deny is added to workspace lints so the next move fails the build
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed all 16 unresolved intra-doc links with real paths (super::/module-qualified, std::ops::Deref). Two link targets were file-private and unreachable from the linking scope: crates/proxy/src/encrypt/unprotected.rs parser_error_kind is now pub(super) (rationale documented on the fn) and crates/proxy/src/config.rs describe_parse_error is now pub(crate). Also cleared the one rustdoc::redundant_explicit_links warning in crates/core/src/transform.rs so cargo doc is warning-free. Added [workspace.lints.rustdoc] broken_intra_doc_links = "deny" to Cargo.toml.
<!-- SECTION:NOTES:END -->
