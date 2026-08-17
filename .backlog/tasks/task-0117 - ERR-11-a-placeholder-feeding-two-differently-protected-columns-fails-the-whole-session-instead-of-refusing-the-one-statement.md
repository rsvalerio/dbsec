---
id: TASK-0117
title: >-
  ERR-11: a placeholder feeding two differently-protected columns fails the
  whole session instead of refusing the one statement
status: To Do
assignee:
  - TASK-0124
created_date: '2026-08-14 16:49'
updated_date: '2026-08-17 20:04'
labels:
  - code-review-rust
  - idioms-correctness
dependencies: []
modified_files:
  - crates/proxy/src/portal.rs
  - crates/proxy/src/encrypt.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**Rule**: ERR-11 (panic/fatal for bugs, `Result` for expected failure)

**File**: `crates/proxy/src/portal.rs:125` (`ParamTransforms::record`), `crates/proxy/src/encrypt.rs:906` and `crates/proxy/src/encrypt.rs:1154` (`index_value`), `crates/proxy/src/encrypt.rs:487`

**What**: `record` returns `Error::ConflictingParameter` when one `$n` is asked to carry two different wire values. That refusal is correct — the Bind has room for one value — but it travels as `Rejection::Fatal`, so `rewrite_sql` returns `Err(*error)` and `relay` logs *"transform failed; closing session"* and tears the connection down.

The triggering SQL is valid client input, not a protocol violation:

```sql
INSERT INTO users (email, backup_email) VALUES ($1, $1)
```

with the two columns configured under different transforms (or different index keys), and

```sql
UPDATE users SET email = $1 WHERE email = $1
```

which needs the sealed value in the SET and the blind index in the WHERE.

Every other statement the rewrite cannot handle goes through `QueryRewriter::unprotected` and becomes a statement-level ErrorResponse under `reject`, or a warning under `warn`. This one shape bypasses that decision point entirely and is fatal under both settings.

**Why it matters**: a client can end its own session with one well-formed statement, and gets `Closed` rather than a `DbError` naming the placeholder — the same diagnostic gap TASK-0064 closed for the read path. Under a connection pool the retry re-sends the same statement and kills the next connection too. The error text (`"placeholder $N feeds two protected positions that need different values"`) is already written for a client audience but never reaches one.

Refusing the statement is the right severity: nothing has been sent upstream at that point, so the write path's existing `SqlOutcome::Refuse` / `awaiting_sync` machinery applies unchanged.

**Note**: this is the residual of TASK-0035, which correctly stopped the double transform; only the blast radius of the resulting error is at issue here.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A conflicting placeholder is refused at statement level with an ErrorResponse naming the placeholder, and the session stays usable
- [ ] #2 In the extended protocol the refusal follows the existing awaiting_sync path, so the batch is discarded up to Sync and answered with ReadyForQuery
- [ ] #3 The refusal happens under both on_unprotected settings, since the statement cannot be honoured either way
- [ ] #4 Tests cover INSERT INTO t (a, b) VALUES ($1, $1) with differing transforms, in both the simple and extended protocols
<!-- AC:END -->
