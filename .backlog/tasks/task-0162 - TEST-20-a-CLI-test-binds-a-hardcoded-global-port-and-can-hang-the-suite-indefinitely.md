---
id: TASK-0162
title: >-
  TEST-20: a CLI test binds a hardcoded global port and can hang the suite
  indefinitely
status: To Do
assignee:
  - TASK-0182
created_date: '2026-08-19 08:31'
updated_date: '2026-08-19 09:01'
labels:
  - code-review-rust
  - test-quality
dependencies: []
modified_files:
  - crates/proxy/tests/cli.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/tests/cli.rs:195`

**What**: `the_plain_relay_opt_in_falls_back_to_the_default_listen_address` binds
`127.0.0.1:6432` with `.ok()`, then spawns `dbsec --plain-relay` and reads `.output()`,
asserting the bind *failure* message. The `.ok()` swallows the case where the test's own bind
fails. If the port is momentarily held by something else that then releases it, `dbsec` binds
successfully — and `dbsec` is a proxy that never exits, while `Command::output()` has no
timeout and `cargo test` has no per-test deadline. The result is an indefinite hang, not a
failure. It is the only non-ignored test that binds a fixed port; every other config uses
`127.0.0.1:0`.

**Why it matters**: the test's own doc identifies the hazard and then adopts a mitigation with
a hole in it. A hang in CI is worse than a failure: it burns the job timeout and produces no
diagnostic.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The test observes the fallback without racing for the port, or binds with expect() so a failed setup fails loudly instead of arming a hang
- [ ] #2 No Command::output() in cli.rs is reachable by an invocation of dbsec that stays running
- [ ] #3 --allow-core-dumps gains at least one spawned-binary case
<!-- AC:END -->
