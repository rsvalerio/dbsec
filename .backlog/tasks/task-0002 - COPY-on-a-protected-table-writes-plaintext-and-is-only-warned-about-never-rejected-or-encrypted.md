---
id: TASK-0002
title: >-
  COPY on a protected table writes plaintext and is only warned about, never
  rejected or encrypted
status: Done
assignee:
  - TASK-0049
created_date: '2026-08-11 20:40'
updated_date: '2026-08-12 16:25'
labels:
  - security
  - encrypt-path
dependencies:
  - TASK-0001
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:279-289`

**What**: `Statement::Copy` is matched only to log a warning when the target table is protected, then returns `Ok(false)`. The bulk-load path that follows — `CopyInResponse`, a stream of `CopyData` messages, `CopyDone` — is relayed byte-for-byte by the session loop and never inspected. `plans/PLAN.md` records this as an accepted caveat ("`COPY FROM` is not encrypted; warn or reject on protected tables"), but only the *warn* half was built; the *reject* half was not.

**Why it matters**: `COPY` is the standard way bulk data actually enters a PostgreSQL table — migrations, restores, ETL, `pg_dump | psql`. It is precisely the path most likely to load a large volume of sensitive rows, and it is the one path with no protection at all. Unlike a stray `INSERT`, a `COPY` poisons the column at scale in one statement.

Two directions worth deciding between (they are not equivalent in cost):
- **Reject** under the strict mode from [[task-0001]] — cheap, correct, blocks a legitimate workflow.
- **Encrypt the `CopyData` stream** — parse the text/CSV format, transform the protected columns, re-emit. Real work, and it must handle `COPY ... WITH (FORMAT binary)` or refuse it explicitly.

**Note**: `COPY TO` (the read direction) is a separate question — it bypasses `DataRow` interception, so protected columns dump as raw ciphertext rather than plaintext. That is fail-safe, but it silently defeats masking and should be confirmed rather than assumed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A decision is recorded in plans/PLAN.md: reject COPY on protected tables, or encrypt the CopyData stream
- [x] #2 COPY FROM on a protected table is rejected with a clear ErrorResponse under strict mode, or encrypted, per that decision
- [x] #3 COPY TO behaviour on a protected table is verified and documented — specifically whether masked columns leak their unmasked stored form
- [x] #4 An e2e case covers COPY against a protected table through the real binary
<!-- AC:END -->
