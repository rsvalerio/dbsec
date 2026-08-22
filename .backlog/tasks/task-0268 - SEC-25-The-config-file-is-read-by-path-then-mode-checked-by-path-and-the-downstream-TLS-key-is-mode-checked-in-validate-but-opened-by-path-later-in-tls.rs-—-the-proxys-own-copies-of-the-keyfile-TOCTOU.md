---
id: TASK-0268
title: >-
  SEC-25: The config file is read by path then mode-checked by path, and the
  downstream TLS key is mode-checked in validate but opened by path later in
  tls.rs — the proxy's own copies of the keyfile TOCTOU
status: Triage
assignee: []
created_date: '2026-08-22 00:38'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/config.rs
  - crates/proxy/src/tls.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/config.rs:537`

**What**: crates/proxy/src/config.rs:537 reads the config with `std::fs::read_to_string(path)` and only afterwards, at config.rs:547-552, calls `check_secret_file_mode(path, ..)` which stats the same path independently. crates/proxy/src/config.rs:601-603 stats `[tls.downstream] key` during validation, and `load_key` (crates/proxy/src/tls.rs:185-188) opens the path again later from `TlsContext::from_config`, explicitly relying on the earlier check ('the mode has already been proved safe', tls.rs:180-184). In both cases the file that was checked is not necessarily the file that was read. TASK-0196 files the same pattern for the core keyfile; these two sites are in the proxy and would not be closed by a core-only fix.

**Why it matters**: A local attacker who can replace the file between the two syscalls (a writable parent directory, a symlink swap) can get a loose-mode file accepted, or a different file read than the one checked. Impact is low — it requires directory write access — but the proxy presents these checks as a guarantee and the keyfile finding will otherwise leave the proxy half-fixed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `Config::load` opens the config once (`File::open`), stats the open handle for the mode check, and reads the content from that same handle
- [ ] #2 `load_key` reads the key through an open handle whose metadata was checked, or `check_secret_file_mode` gains a handle-based variant that `Config::validate` and `load_key` share
- [ ] #3 The SEC-29 tests for the config file and the TLS key still pass, and the tls.rs doc on `load_key` describes the handle-based guarantee
<!-- AC:END -->
