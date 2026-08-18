---
id: TASK-0136
title: >-
  standard_conforming_strings set in the startup packet is not tracked, unlike
  search_path
status: Done
assignee:
  - TASK-0140
created_date: '2026-08-18 09:37'
updated_date: '2026-08-18 14:27'
labels:
  - code-review-rust
  - security
  - sql-rewrite
dependencies: []
modified_files:
  - crates/proxy/src/session.rs
  - crates/proxy/src/encrypt.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/session.rs:240` (`search_path_is_default`), `crates/proxy/src/encrypt.rs` (`QueryRewriter::new`, the `escape_strings` field)

**What**: TASK-0122 made a mid-session `standard_conforming_strings = off` an
`on_unprotected` site, matching what `search_path` already got. The connect-time half is
still missing: `QueryRewriter::new` hardcodes `escape_strings: false`, and
`search_path_is_default` reads only `search_path` and `options` out of the startup
message. A client can set the GUC in the StartupMessage parameter list, or through
`options=-c standard_conforming_strings=off`, and the proxy will never notice.

**Why it matters**: the same divergence the in-session case now reports, reached by a
spelling that is not checked. From the first statement onward, PostgreSQL reads a
backslash in an ordinary `'…'` literal as the start of an escape while sqlparser reads it
as a backslash, so a value bound to a protected column is sealed as the proxy read it
rather than as the client wrote it — unrecoverable, and silent, because nothing
downstream can tell it apart from a correctly sealed value. Not filed as part of
TASK-0122 because `session.rs` is outside that wave's file scope and the fix changes
`QueryRewriter::new`'s signature.

**Fix shape**: widen `search_path_is_default` into one startup scan that reports both
settings (`search_path` moved, `standard_conforming_strings` off), thread the second flag
through `Started` and `QueryRewriter::new` next to `search_path_trusted`, and report it
as `Unprotected::EscapeStringsChanged` on the first statement the way the in-session path
does.

**Origin**: discovered during TASK-0122 while fixing TASK-0100.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A startup packet that sets standard_conforming_strings off (directly or via options=-c) puts the session in the same state a mid-session SET does
- [x] #2 A test covers both startup spellings
<!-- AC:END -->
