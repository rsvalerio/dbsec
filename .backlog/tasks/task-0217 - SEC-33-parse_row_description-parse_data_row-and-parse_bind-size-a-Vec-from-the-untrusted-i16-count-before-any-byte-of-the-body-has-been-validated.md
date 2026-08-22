---
id: TASK-0217
title: >-
  SEC-33: parse_row_description, parse_data_row and parse_bind size a Vec from
  the untrusted i16 count before any byte of the body has been validated
status: Triage
assignee: []
created_date: '2026-08-21 19:48'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/pgwire/src/lib.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
<!-- scan confidence: candidates to inspect -->

**File**: `crates/pgwire/src/lib.rs:165` (`parse_row_description`, `Vec<RowField>` = 40 bytes/elem), `:186` (`parse_data_row`, `Vec<Option<&[u8]>>` = 16 bytes/elem), `:295` and `:300` (`parse_bind`), `:271` (`result_format_codes`)

**What**: Each parser calls `Vec::with_capacity(count.max(0) as usize)` straight from the 2-byte count field, before checking that the body could possibly contain that many entries. A 2-byte `T` body of `0x7FFF` with nothing after it allocates ~1.3 MiB (`32767 * size_of::<RowField>()`) and then fails on the first `take_cstr`; a `D` body does ~512 KiB. The minimum bytes-per-entry is known at each site (RowDescription: 19 bytes per field; DataRow/Bind params: 4 per value; formats: 2 per code), so `count` can be bounded by `body.len() / min_entry_len` before sizing the Vec.

**Why it matters**: Low on its own — the allocation is transient, freed on the error path, and bounded by the per-frame `MAX_MESSAGE_LEN` and the session limits already filed under SEC-33 (TASK-0009, TASK-0128). But it is the one remaining place in the crate where an attacker-chosen field, not the actual bytes received, decides an allocation size, and it runs per frame on the backend → client path where a compromised or impersonated server could emit `T` frames at line rate. It is also a cheap, local fix that makes the "the allocation never happens" argument in `startup_body_len` (line 117) true for the body parsers too.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Vec capacity at each site is min(count, body.len() / minimum_entry_len) or the parser rejects count * minimum_entry_len > body.len() up front as malformed
- [ ] #2 A unit test feeds count = i16::MAX with an empty body to each parser and asserts Err without relying on allocation size
<!-- AC:END -->
