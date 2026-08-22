---
id: TASK-0222
title: >-
  DUP-2: seal_expr, open_expr and mask_expr each re-implement the
  Option-wrapping and Text/Bytes borrow-and-convert scaffolding around a
  one-line core
status: Triage
assignee: []
created_date: '2026-08-21 19:49'
labels:
  - code-review-rust
  - duplication
dependencies: []
modified_files:
  - crates/derive/src/lib.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/derive/src/lib.rs:360-473`

**What**: Three `ProtectedField` methods have the same shape: (1) a `match self.shape.repr` picking `as_bytes()` vs `as_slice()`/`AsRef::<[u8]>`, (2) a `match` picking `String::from_utf8(..).map_err(|_| Error::Malformed)?` vs pass-through for the way back, (3) an `if self.shape.optional { quote!{ match &__record.#ident { Some(__value) => Some(#one), None => None } } } else { quote!{ { let __value = &__record.#ident; #one } } }` wrapper. `seal_expr` and `open_expr` are character-for-character identical in (3); `mask_expr` repeats (1)/(2) with `into_owned()` and a slightly different (3) over `__out`. Only the inner `protector.seal/open/mask(..)` call differs. Note too that `seal_expr` uses `::core::convert::AsRef::<str>::as_ref(__value).as_bytes()` while `open_expr`/`mask_expr` use `__value.as_bytes()` for the same repr — the fully-qualified form is the hygienic one and the other two should match.

**Why it matters**: DUP-2 (3 functions of the same structure differing in a literal). The shape/optional logic is the part most likely to gain a case (a `Cow`, a `&str` field, `Option<Option>` rejection moving) and currently has to be edited in three places that can drift — the existing `as_bytes` inconsistency is already that drift. Extract `fn borrow_bytes(&self) -> Tokens`, `fn from_bytes(&self, repr: Repr, value: Tokens) -> Tokens`, and `fn per_value(&self, source: Tokens, one: Tokens) -> Tokens` for the Option wrapper.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The Option-wrapping and repr conversion tokens are produced by shared helpers used by all three expression builders
- [ ] #2 All three builders use the same fully-qualified as-bytes form
<!-- AC:END -->
