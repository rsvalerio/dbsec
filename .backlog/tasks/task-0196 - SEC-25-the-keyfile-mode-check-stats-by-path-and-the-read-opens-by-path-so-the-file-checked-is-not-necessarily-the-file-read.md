---
id: TASK-0196
title: >-
  SEC-25: the keyfile mode check stats by path and the read opens by path, so
  the file checked is not necessarily the file read
status: Triage
assignee: []
created_date: '2026-08-21 19:31'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/core/src/keys.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/keys.rs:106` (also `crates/core/src/keys.rs:181`)

**What**: `check_secret_file_mode` does `std::fs::metadata(path)` and returns; `FileKeySource::load` later does `std::fs::read_to_string(path)` as an independent open. Between the two calls the path can be re-pointed (rename, symlink swap), so the permission decision is made on one inode and the bytes come from another. The vault crate calls the same helper ahead of its own token read (`crates/vault/src/lib.rs:270,286`). The check is deliberately lenient on a stat failure, which is fine, but the fix for the race is structural: open first, then `File::metadata()` on the handle, then read from that handle.

**Why it matters**: A check-then-use permission gate is a classic TOCTOU; the window needs local write access to the parent directory, so the severity is Low, but the helper is the workspace's single secret-file gate and is called from three places, so closing it once closes it everywhere.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The mode check and the read operate on the same open file handle (open → fstat via File::metadata → read), for FileKeySource::load and for callers that read a secret after checking it
- [ ] #2 check_secret_file_mode (or a handle-taking variant) is what the proxy and vault callers use, so no caller stats by path and then opens by path
- [ ] #3 Existing keyfile permission tests still pass
<!-- AC:END -->
