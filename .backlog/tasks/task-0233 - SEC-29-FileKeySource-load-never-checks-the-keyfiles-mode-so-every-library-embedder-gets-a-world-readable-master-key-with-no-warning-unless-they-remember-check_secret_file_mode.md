---
id: TASK-0233
title: >-
  SEC-29: FileKeySource::load never checks the keyfile's mode, so every library
  embedder gets a world-readable master key with no warning unless they remember
  check_secret_file_mode
status: Triage
assignee: []
created_date: '2026-08-21 19:50'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/core/src/keys.rs
  - crates/core/examples/embedded.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/keys.rs:174-186` (also `crates/core/src/keys.rs:102`, `crates/core/examples/embedded.rs:57-60`, `crates/core/src/lib.rs:101`)

**What**: `check_secret_file_mode` exists in this crate, but `FileKeySource::load` does not call it — the doc comment delegates that to "the caller" and notes that the proxy does it (TASK-0019 closed the proxy side). The library's own consumers do not: the crate docs introduce `FileKeySource` as the keyfile source for development with no mention of the check, and `examples/embedded.rs` — the runnable template `make e2e` executes and the README points at — writes every DEK and index key with `std::fs::write`, which creates the file at the umask default (`0644`), then loads it without a check. `generate` is careful to create the file at `0600`; `load` is the only half that trusts its caller.

**Why it matters**: SEC-29 says secret files must be verified not world-readable by the code that reads them, not by convention. The proxy's fix covers one of three current callers; a published library API whose safe use depends on a second call the docs never mention is the same finding again for every future embedder. `load` can perform the check itself (against the open handle, which also resolves TASK-0196's TOCTOU) and the example should create its keyfile through `generate` or with mode `0600`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 FileKeySource::load refuses a keyfile readable beyond its owner with Error::SecretFileMode, or documents an explicit opt-out for callers that have already checked
- [ ] #2 examples/embedded.rs creates its keyfile with mode 0600 (via FileKeySource::generate or OpenOptionsExt::mode)
- [ ] #3 A test under the keyfile feature loads a 0644 keyfile and asserts the refusal
<!-- AC:END -->
