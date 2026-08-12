---
id: TASK-0024
title: >-
  SEC-5: FileKeySource leaves master key material in un-zeroized heap
  allocations
status: To Do
assignee:
  - TASK-0053
created_date: '2026-08-11 19:23'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - security
  - crypto
dependencies: []
modified_files:
  - crates/core/src/keys.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/keys.rs:54-66`, `crates/core/src/keys.rs:86-90`

**What**: The crate is deliberate about zeroization — `Key` is `Zeroizing<[u8; 32]>`, and `decode` zeroizes its intermediate `Vec` (line 123). The hex path around it defeats that intent, in three places:

- line 54 — `let raw = std::fs::read_to_string(path)?` holds the *entire keyfile*, every DEK and every deterministic index key as hex, in a plain `String`. It is dropped at the end of `load` without being zeroized.
- lines 56-66 — `parsed: KeyFile` owns `HashMap<String, String>` for both `keys` and `index_keys`. Each value is 64 hex chars of key material in its own heap allocation. `decode_key` reads from these and zeroizes only its own decoded buffer; the source strings are dropped intact.
- lines 86-90 — `generate` wraps the final keyfile text in `Zeroizing<String>`, but `hex::encode(key.as_ref())` builds an un-zeroized `String` of the fresh DEK first, and `format!` may reallocate its buffer mid-build, leaving further copies behind.

**Why it matters**: This is the master key material for the whole product — TASK-0019 makes the same point about the file on disk. Freed-but-not-overwritten heap is exactly what a core dump, a swapped page, a hypervisor snapshot, or a subsequent heap-overread bug (Heartbleed's shape) exposes. Two full plaintext copies of every key survive `load`, so the `Zeroizing<[u8; 32]>` on the stored copy buys much less than it appears to. The cost of fixing it is low: read the file into a `Zeroizing<String>`, deserialize into a `KeyFile` whose string fields are `Zeroizing<String>` (or zeroize them in a manual `Drop`), and build the generated contents by writing hex directly into the `Zeroizing<String>`.

Note that TOML deserialization makes complete erasure best-effort — `toml` allocates its own intermediate buffers. The goal is to remove the copies this crate owns and can name, not to claim a guarantee the parser cannot give.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The keyfile contents read in FileKeySource::load are held in a zeroize-on-drop container rather than a plain String
- [ ] #2 The hex key strings deserialized into KeyFile are zeroized when the KeyFile is dropped
- [ ] #3 FileKeySource::generate writes hex key material into a zeroizing buffer without an intermediate un-zeroized String
- [ ] #4 A comment records that toml's own intermediate allocations are outside this crate's control, so erasure is best-effort
<!-- AC:END -->
