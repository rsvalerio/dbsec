---
id: TASK-0101
title: >-
  Key material type derives Debug, so an accidental debug-print would log raw
  key bytes
status: Triage
assignee: []
created_date: '2026-08-14 14:06'
labels:
  - security-review
  - security
  - crypto
dependencies: []
modified_files:
  - crates/core/src/keys.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/keys.rs:14` (`Key = Zeroizing<[u8; 32]>`).

**What**: `zeroize::Zeroizing` derives `Debug`, so `Key` prints its raw bytes if ever Debug-formatted. No production site does today (verified), but any future `?key` in a `tracing` call, or a `#[derive(Debug)]` on a struct that holds a `Key`, compiles silently and logs raw key material.

**Why it matters**: latent key-logging footgun in a codebase that otherwise hand-writes redacting `Debug` for secret-bearing types (`Secret`, `IndexKeyRecord`, `TlsContext`).

**Fix shape**: wrap key material in a newtype with a redacting `Debug` (the treatment secret types already get), so an accidental debug-print cannot compile to a raw-bytes log.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Key material cannot be Debug-formatted into its raw bytes
- [ ] #2 A struct holding a Key can derive Debug without exposing key material
<!-- AC:END -->
