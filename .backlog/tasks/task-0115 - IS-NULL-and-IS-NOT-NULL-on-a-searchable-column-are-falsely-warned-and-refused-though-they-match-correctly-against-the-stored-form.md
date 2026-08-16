---
id: TASK-0115
title: >-
  IS NULL and IS NOT NULL on a searchable column are falsely warned and refused,
  though they match correctly against the stored form
status: Done
assignee: []
created_date: '2026-08-14 16:49'
updated_date: '2026-08-14 20:26'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**Rule**: SEC-31 (fail-closed calibration — a false refusal is as costly as a false pass), READ-5

**File**: `crates/proxy/src/encrypt.rs:1091` (`searchable_operand`), `crates/proxy/src/encrypt.rs:815` (`rewrite_selection` fallthrough), `crates/proxy/src/encrypt.rs:1122` (`expr_shape`)

**What**: `searchable_operand` treats `Expr::IsNull` and `Expr::IsNotNull` as predicates it cannot express, so `rewrite_selection`'s `_ =>` arm sends them to `unprotected(&Unprotected::Predicate { shape: "IS NULL" })`.

But nullness survives sealing exactly. `seal_expr` returns early on `Expr::Value(Value::Null)` and Bind leaves a NULL parameter untouched (`let Some(Some(value)) = values.get_mut(*index) else { continue }`), so a NULL in a protected column is stored as SQL NULL and a non-NULL is stored as a non-NULL envelope. `col IS NULL` and `col IS NOT NULL` therefore return exactly the rows the client meant — no blind index is needed and none would help.

Confirmed under `on_unprotected = "reject"`:

```
SELECT id FROM users WHERE email IS NULL
  -> ErrorResponse 42501: "searchable column email was used in a IS NULL,
     which cannot be matched against its blind index"
```

Under the default `warn` the same statement runs correctly but emits a warning saying "it will match no rows", which is false.

**Why it matters**: `WHERE col IS NOT NULL` is routine in migrations, backfills, partial-index-friendly queries and nullability audits. Refusing it makes `reject` mode reject working SQL for no benefit, which is the main reason a deployment stays on `warn` — and `warn` is fail-open. Warning about it also dilutes the warning stream that is meant to be the operator's to-do list: a signal that fires on correct queries stops being read. Same family as TASK-0112 (`DO UPDATE SET col = EXCLUDED.col` falsely refused).

`IsDistinctFrom` / `IsNotDistinctFrom` are *not* in the same position — `col IS DISTINCT FROM 'literal'` genuinely compares against the stored form — so only the two null tests should be exempted.

**Why it matters for scope**: this is a false-positive fix only; no statement that currently passes should start being refused.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 WHERE col IS NULL and WHERE col IS NOT NULL on a searchable column are relayed unchanged with no warning under warn and no refusal under reject
- [x] #2 IS DISTINCT FROM / IS NOT DISTINCT FROM against a non-NULL operand remain on_unprotected sites
- [x] #3 Tests cover both null tests under both on_unprotected settings, in WHERE and in a JOIN ON constraint
<!-- AC:END -->
