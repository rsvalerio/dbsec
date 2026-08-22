---
id: TASK-0212
title: >-
  ERR-11: struct_attrs builds the row_key Ident with Ident::new, which panics on
  a non-identifier string and turns a user typo into a proc-macro panic
status: Triage
assignee: []
created_date: '2026-08-21 19:47'
labels:
  - code-review-rust
  - idioms
dependencies: []
modified_files:
  - crates/derive/src/lib.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/derive/src/lib.rs:518-521`

**What**: `row_key = "..."` is read as a string literal and then fed to `Ident::new(&name, nv.value.span())`. `proc_macro2::Ident::new` panics ("\"...\" is not a valid Ident") for anything that is not a Rust identifier — `row_key = "user id"`, `row_key = ""`, `row_key = "my-id"`, `row_key = "0id"`, or a raw keyword like `"type"`. Every other input mistake in this crate is reported as a spanned `syn::Error` via `to_compile_error()`, but this one escapes as `proc-macro derive panicked` with the panic message and no span on the offending attribute.

**Why it matters**: ERR-11 — a panic is for an internal invariant, and a string the user typed is expected input, not an invariant. The derive already has an error path (`Err(Error::new(span, ..))`) and a downstream check ("row_key must name an unprotected field of this struct") that this panic pre-empts. Use `syn::parse_str::<Ident>(&name)` (or `Ident::new` guarded by `syn::ext::IdentExt` / a manual validity check) and map the failure to `Error::new(nv.value.span(), ..)`. Alternatively accept `row_key = id` (a path) in addition to the string form, which gives a real `Ident` with a real span for free.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A non-identifier row_key string produces a spanned compile error pointing at the attribute, not a proc-macro panic
- [ ] #2 A compile-fail test (trybuild or equivalent) covers at least one invalid row_key spelling
<!-- AC:END -->
