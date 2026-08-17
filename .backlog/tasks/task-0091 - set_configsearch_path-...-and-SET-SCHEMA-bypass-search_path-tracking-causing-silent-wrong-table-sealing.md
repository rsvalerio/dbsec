---
id: TASK-0091
title: >-
  set_config('search_path', ...) and SET SCHEMA bypass search_path tracking,
  causing silent wrong-table sealing
status: To Do
assignee:
  - TASK-0122
created_date: '2026-08-14 14:06'
updated_date: '2026-08-17 20:04'
labels:
  - security-review
  - security
  - sql-rewrite
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:504-514` (`note_session_state`).

**What**: `note_session_state` reacts only to `Statement::SetVariable`, so only a literal `SET [SESSION|LOCAL] search_path = ...` flips `search_path_trusted`. `SELECT set_config('search_path','tenant7',false)` parses as an ordinary query and passes through; `SET SCHEMA 'tenant7'` is not a `SetVariable` in sqlparser 0.53. In all these cases `search_path_trusted` stays `true`, so the write path keeps resolving unqualified names to `public` and keeps sealing. Verified against source. Extends the closed SEC-11 tracking.

**Why it matters**: not a plaintext leak (the proxy over-seals rather than under-seals), but an unqualified `INSERT INTO users (email) ...` after `set_config` seals for `public.users` while the row lands in `tenant7.users`, which the read path (keyed on the `public.users` OID/attnum) can never decrypt — silent data corruption. And under `reject`, a `SET search_path` is refused while `set_config('search_path',...)` is not, so operators may believe search_path is pinned when it is not (incomplete mediation).

**Fix shape**: also match `set_config('search_path', ...)` (and, if parseable, `SET SCHEMA`) in `note_session_state`, or document the limitation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A search_path change made via set_config is detected the same as SET search_path
- [ ] #2 Under reject a set_config search_path change is refused like SET search_path
- [ ] #3 A test covers set_config('search_path', ...) followed by an unqualified write
<!-- AC:END -->
