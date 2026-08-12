---
id: TASK-0029
title: >-
  SEC-37: mask.rs and the FPE read path take untrusted stored bytes but are
  neither fuzzed nor property-tested
status: To Do
assignee:
  - TASK-0054
created_date: '2026-08-11 19:24'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - security
  - tests
dependencies: []
modified_files:
  - crates/core/src/mask.rs
  - crates/core/src/transform.rs
  - crates/core/tests/props.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/mask.rs:32-54`, `crates/core/src/transform.rs:137-157`, `fuzz/fuzz_targets/`

**What**: The fuzz corpus covers two of the four modules that consume untrusted bytes. `fuzz/fuzz_targets/envelope.rs` covers `envelope` and `blind_index::split`; `fuzz/fuzz_targets/pgwire.rs` covers every `pgwire` parser and both encode/parse roundtrips — that part is well done. Neither the fuzz targets nor `crates/core/tests/props.rs` touch:

- `MaskSpec::apply` (`mask.rs:32`) — runs on whatever the database returned, including arbitrary non-UTF-8 bytes, with a UTF-8 branch, a char-vs-byte length distinction, and a `keep_first + keep_last` arithmetic guard. It has three unit tests and no generated input.
- `FpeTransform::transform_digits` (`transform.rs:137`) — on the `open` path this runs FF1 decryption over arbitrary stored bytes, indexing back into the value by recorded digit positions (`result[position] = b'0' + digit as u8`) and zipping two vectors whose lengths the code assumes match.
- `EncryptTransform::open` (`transform.rs:92`) — the branch selection over `blind_index::split` and `is_enveloped`, which TASK-0026 shows is where the interesting behaviour lives.

`props.rs` proves these never panic for `envelope` and `pgwire` (`decrypt_never_panics_on_arbitrary_input`, `backend_message_parsers_never_panic`) but has no equivalent for the transform or mask layers.

**Why it matters**: SEC-37 asks for fuzzing on code that handles untrusted input, and these qualify: the whole point of the read path is that it processes bytes an attacker with database write access — the threat model the product exists to address — can choose. `MaskSpec::apply` in particular is a security control, so a case where it returns fewer mask characters than it should is a disclosure bug, not just a crash. A property test can assert the actual invariant rather than only absence of panic: *no output character at a masked position equals the corresponding input character*, and *output length matches input length in chars for UTF-8 input*.

The existing targets are a good template — extending them is mostly mechanical. Note that a transform fuzz target needs a fixed test key, exactly as `fuzz_targets/envelope.rs` already does with `const KEY: [u8; 32] = [7u8; 32]`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A fuzz target exercises MaskSpec::apply, FpeTransform::open and EncryptTransform::open on arbitrary bytes under a fixed test key
- [ ] #2 props.rs gains a property test asserting the masking invariant, not only absence of panic: masked positions never equal the input, and char-length is preserved for UTF-8 input
- [ ] #3 props.rs gains a never-panics property for the transform open path on arbitrary stored bytes
- [ ] #4 The new fuzz targets are wired into whatever CI or Makefile target runs the existing ones
<!-- AC:END -->
