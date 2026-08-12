---
id: TASK-0045
title: >-
  SEC-31: INSERT ... ON CONFLICT DO UPDATE and MERGE write plaintext into
  protected columns with no warning at all
status: To Do
assignee:
  - TASK-0049
created_date: '2026-08-11 21:04'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - security
  - encrypt-path
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:202-239`, `crates/proxy/src/encrypt.rs:290`

**What**: The `Statement::Insert` arm rewrites exactly one thing — the `VALUES` rows reached through `insert.source`:

```rust
let Some(source) = insert.source.as_mut() else { return Ok(false) };
let SetExpr::Values(values) = source.body.as_mut() else { ... };
for row in &mut values.rows {
    for (position, transform) in &protected {
        if let Some(expr) = row.get_mut(*position) { changed |= seal_expr(expr, transform, params)?; }
    }
}
```

The conflict action of the same statement is never inspected. `INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email` seals `$2` for the VALUES path and leaves the `DO UPDATE SET` assignment completely alone — the same protected column, in the same statement, on the branch that actually runs for every existing row. `DO UPDATE SET email = 'someone@example.com'` writes that literal to disk untouched.

`MERGE` is the same hole via a different door: `Statement::Merge` is not matched, so it falls into the catch-all at line 290:

```rust
_ => Ok(false),
```

Upsert is the normal write shape for the sync/ETL workloads this proxy sits in front of.

**Why it matters**: This is a strictly worse case than the six paths already tracked in [[task-0001]]. Those at least emit a `tracing::warn!`, so an operator watching logs can see the invariant break. These two emit **nothing**. `rewrite_statement` returns `Ok(false)` — indistinguishable from "this statement touched no protected table" — so there is no log line, no metric, no signal of any kind that a protected column just took a plaintext write. Whatever fail-closed switch [[task-0001]] adds will not cover these either, because a strict mode built on those six warn sites has no hook here to fire from.

The damage is also self-reinforcing. Plaintext rows written this way are indistinguishable to the read path from pre-migration legacy plaintext, so they relay straight back out and never surface as a decrypt failure. An upsert-driven job silently converts a protected column back to cleartext one conflicting row at a time.

`ON CONFLICT DO UPDATE` assignments are the same `Assignment { target, value }` shape the `Statement::Update` arm at line 240-257 already handles correctly, so the sealing logic exists and just is not reached from here.

<!-- scan confidence: the two gaps are established from encrypt.rs itself (the Insert arm reads only table_name/columns/source; Merge hits the `_` catch-all). The exact sqlparser 0.53 accessor for the conflict action was not verified against the crate source — confirm the field name when implementing. -->
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The conflict action of INSERT ... ON CONFLICT DO UPDATE is walked and its assignments to protected columns are sealed, reusing the same path as Statement::Update
- [ ] #2 A statement shape that touches a protected table but is not rewritten emits a warning rather than returning Ok(false) silently, so it is visible to log-based alerting and to any future strict mode
- [ ] #3 MERGE against a protected table is either rewritten or explicitly warned about, not swallowed by the catch-all arm
- [ ] #4 A test asserts INSERT ... ON CONFLICT DO UPDATE SET <protected> = <literal> stores ciphertext, for both an inline literal and a bound placeholder
- [ ] #5 A test asserts MERGE against a protected table does not silently return Ok(false)
<!-- AC:END -->
