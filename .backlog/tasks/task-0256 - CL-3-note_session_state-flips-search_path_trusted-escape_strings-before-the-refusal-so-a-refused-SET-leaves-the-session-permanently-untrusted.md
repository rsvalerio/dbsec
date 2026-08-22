---
id: TASK-0256
title: >-
  CL-3: note_session_state flips search_path_trusted/escape_strings before the
  refusal, so a refused SET leaves the session permanently untrusted
status: Triage
assignee: []
created_date: '2026-08-21 19:55'
labels:
  - code-review-rust
  - cognitive-load
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/statement.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/statement.rs:110`

**What**:
```rust
SettingMoved::SearchPath => {
    self.search_path_trusted = false;
    self.unprotected(&Unprotected::SearchPathChanged)?;
}
SettingMoved::EscapeStrings => {
    self.escape_strings = true;
    self.unprotected(&Unprotected::EscapeStringsChanged)?;
}
```
Under `reject` the `SET search_path ...` statement is refused and never reaches the server, yet the proxy records the move as if it had. Every subsequent unqualified statement over a protected table in that session is refused with "users is unqualified and this session changed search_path" (`Unprotected::SearchPath`, mod.rs:481), and every later backslash literal as `AmbiguousLiteral`, although the server's settings are unchanged. (The startup-packet path is correct — those settings did take effect.)

**Why it matters**: one refused `SET` wedges the connection for valid SQL with a misleading message; for pooled connections the poisoned session is reused by other requests — the availability false positive mod.rs:300-302 warns keeps operators on warn.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 State is updated only after unprotected returns Ok(()) (i.e. under warn), or is rolled back on Refused
- [ ] #2 Test: under reject, after a refused SET search_path TO tenant7, INSERT INTO users (email) VALUES ('a@b.io') is still sealed and relayed (same for SET standard_conforming_strings = off followed by a backslash literal)
<!-- AC:END -->
