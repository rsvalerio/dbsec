---
id: TASK-0001
title: >-
  SEC: no fail-closed mode — six passthrough paths write plaintext into
  protected columns with only a warning
status: To Do
assignee:
  - TASK-0049
created_date: '2026-08-11 20:40'
updated_date: '2026-08-11 22:42'
labels:
  - security
  - encrypt-path
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:173,179,209,226,284,502`

**What**: Six distinct code paths give up on rewriting a write and let the statement through unmodified, each emitting only a `tracing::warn!`:

| Line | Condition |
|---|---|
| 173 | query is not valid UTF-8 |
| 179 | sqlparser cannot parse the SQL |
| 209 | `INSERT` without a column list on a protected table |
| 226 | `INSERT ... SELECT` into a protected table |
| 284 | `COPY` on a protected table (see [[task-0002]]) |
| 502 | non-literal expression bound to a protected column |

In every case the plaintext reaches the column unencrypted. `plans/PLAN.md` states "Crypto errors fail closed" — that holds for `seal`/`open` failures, but *routing* failures like these do not. `Config` (`crates/proxy/src/config.rs:12-32`) has no strict/fail-closed switch, so there is no deployment in which these are errors.

**Why it matters**: The proxy's entire value is the invariant "a configured column is never at rest in plaintext". Each of these paths silently breaks it, and the breakage is invisible to the client — the `INSERT` succeeds and returns a normal tag. A single unparseable statement from an ORM, or one `INSERT` without a column list, permanently poisons the column with plaintext rows that later reads will pass straight through (the read path treats non-magic values as legacy plaintext by design). Warnings in a log do not stop this; operators discover it by querying the table.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Config gains a strict/fail-closed setting (default decided and documented) that turns each of the six passthrough paths into an ErrorResponse to the client instead of a warning
- [ ] #2 The error is a well-formed PostgreSQL ErrorResponse the session can recover from, not a dropped connection
- [ ] #3 Warnings retain their current wording and fields when strict mode is off, so existing log-based alerting keeps working
- [ ] #4 A test asserts that each of the six conditions is rejected under strict mode and passed through under permissive mode
- [ ] #5 plans/PLAN.md's "Crypto errors fail closed" line is amended to state exactly which failures fail closed under which setting
<!-- AC:END -->
