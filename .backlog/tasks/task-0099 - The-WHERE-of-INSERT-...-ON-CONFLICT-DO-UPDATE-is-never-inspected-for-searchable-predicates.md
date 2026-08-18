---
id: TASK-0099
title: >-
  The WHERE of INSERT ... ON CONFLICT DO UPDATE is never inspected for
  searchable predicates
status: Done
assignee:
  - TASK-0121
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:25'
labels:
  - security-review
  - sql-rewrite
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:606-617` (`OnConflictAction::DoUpdate`).

**What**: for `INSERT ... ON CONFLICT DO UPDATE`, only `update.assignments` is sealed; sqlparser's `DoUpdate.selection` (the conflict-action `WHERE`) is dropped. A searchable equality there — `... ON CONFLICT (id) DO UPDATE SET x = 1 WHERE users.email = 'secret'` — is silently not rewritten and not flagged. Same class as the UPDATE...FROM/DELETE...USING gap, narrower reach (the assignment *values* are correctly sealed). Verified against source.

**Why it matters**: a searchable predicate in a DO UPDATE WHERE compares plaintext against the blind-index stored form and silently matches nothing (or the wrong rows), with no warning in either mode.

**Fix shape**: run `rewrite_selection` over `DoUpdate.selection` with the target-table scope, like the other predicate sites.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A searchable predicate in a DO UPDATE WHERE is rewritten or routed through the on_unprotected gate
- [x] #2 A test covers ON CONFLICT DO UPDATE with a searchable equality in its WHERE
<!-- AC:END -->
