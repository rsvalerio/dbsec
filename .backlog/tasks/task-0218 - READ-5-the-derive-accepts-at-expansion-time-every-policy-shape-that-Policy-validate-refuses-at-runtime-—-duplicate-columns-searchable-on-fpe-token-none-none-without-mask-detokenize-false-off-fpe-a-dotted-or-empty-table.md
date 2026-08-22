---
id: TASK-0218
title: >-
  READ-5: the derive accepts at expansion time every policy shape that
  Policy::validate refuses at runtime — duplicate columns, searchable on
  fpe/token/none, none without mask, detokenize = false off fpe, a dotted or
  empty table
status: Triage
assignee: []
created_date: '2026-08-21 19:48'
labels:
  - code-review-rust
  - structure
dependencies: []
modified_files:
  - crates/derive/src/lib.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/derive/src/lib.rs:113-147` (expand), `:507-547` (struct_attrs), `:550-601` (field_attrs), `:475-502` (policy_expr)

**What**: `#[derive(Protect)]` has every fact it needs to reject an invalid policy with a spanned compile error, but it emits the policy verbatim and leaves the refusal to `Policy::validate` inside `Protector::new` — i.e. to the first run of the application, as `Error::Policy(String)` with no source location. Concretely, all of these compile today and fail at runtime:

- two fields with `column = "x"` (or a field `x` plus another with `column = "x"`) → "duplicate column entry" (`crates/core/src/policy.rs:284`)
- `#[dbsec(fpe, searchable)]`, `#[dbsec(token, searchable)]`, `#[dbsec(none, searchable)]` → "searchable requires transform = encrypt" (`policy.rs:286`)
- `#[dbsec(none)]` with no `mask` → "transform = none does nothing without a mask" (`policy.rs:296`)
- `#[dbsec(detokenize = false)]` on an encrypt/token field → "detokenize = false is only meaningful for fpe" (`policy.rs:291`)
- `table = ""` (becomes `public.`), `table = "a.b.c"` (split_once keeps the whole string), or a column/table with characters `check_identifiers` refuses

**Why it matters**: The skill's design philosophy and README promise "prefer compile-time enforcement over runtime checks" — the whole point of a derive over a TOML policy is that the struct *is* the checked declaration. Today a typo in an attribute ships, and is discovered when `Protector::new` refuses the policy at startup with a message that names a qualified column but not the struct or field. Each check above is a few lines in `expand` / `field_attrs` with the field's span available; `column` uniqueness is a `HashSet<String>` over `protected`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each listed invalid combination is a spanned compile error on the offending attribute or field
- [ ] #2 The derive-time checks mirror Policy::validate (shared helper or documented parity) so the two cannot drift
- [ ] #3 Compile-fail tests cover each rejected combination
<!-- AC:END -->
