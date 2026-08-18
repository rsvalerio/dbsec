---
id: TASK-0107
title: >-
  Read-path decryption amplifies memory ~3-4x per DataRow, so one frame near the
  1 GiB cap exhausts memory
status: Done
assignee:
  - TASK-0125
created_date: '2026-08-14 18:16'
updated_date: '2026-08-17 20:22'
labels:
  - security-review
  - security
  - dos
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
  - crates/core/src/pgwire.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:345` (`decrypt_row`), `:395` (`decode_wire`), `:373-376` (hex re-encode); `crates/core/src/pgwire.rs:126` (`encode_data_row`).

**What**: decrypting a single hex-text BYTEA column allocates, in sequence and partly concurrently: `hex::decode` (the wire bytes), the opened plaintext (`transform.open`), `hex::encode(replacement)` → `String`, the `format!("\\x{…}")` → `String` → `into_bytes`, and finally a full row copy in `pgwire::encode_data_row` (`Vec::with_capacity(2 + n*4 + payload)`). The frame-length check in `encode_frame_header` fires only *after* all of these allocations, so it does not bound the transient peak.

**Why it matters**: a malicious or compromised backend (or a large client-written value echoed back on read) sending a DataRow near the 1 GiB `MAX_MESSAGE_LEN` cap with a protected column drives peak resident memory to several GiB for that one frame — on top of the 1 GiB relay `body` buffer still held in `relay`. Multiplied by `max_sessions` concurrent sessions this is a memory-exhaustion DoS. task-0009 covers only the 1 GiB relay buffer; this per-DataRow read-path amplification is a separate multiplier the existing bound does not address.

**Fix shape**: cap the per-value size the read path will decrypt/re-encode (reject or pass through oversized protected values), and/or stream the hex re-encode into the output buffer in place instead of building three intermediate `String`/`Vec` copies. Consider a configurable per-value ceiling well below the frame cap.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Peak transient allocation per decrypted DataRow is bounded to a small multiple of the value size, not 3-4x an arbitrary near-1-GiB frame
- [x] #2 A per-value size ceiling (or streaming re-encode) is enforced before the intermediate copies are built
- [x] #3 A test exercises a large protected BYTEA value and asserts the bound
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed on code-review/TASK-0125.

- `rows::MAX_PROTECTED_VALUE_LEN` (16 MiB) caps the wire length of a single
  protected column value, checked before `decode_wire`/`open`/mask/re-encode
  build any copy of it. Over the ceiling the row is *refused*
  (`Error::ProtectedValueTooLarge`, added to `is_refusal`), so the client gets
  an ErrorResponse and the session closes rather than being handed a protected
  column's stored form.
- `hex_text_form` replaces `format!("\\x{}", hex::encode(v))`: one right-sized
  buffer via `hex::encode_to_slice` instead of two intermediate `String`s.
- `decrypt_row` now tracks the row's projected re-encoded size and refuses
  (`Error::FrameTooLarge`) as soon as it would exceed what a frame header can
  express, instead of assembling the whole oversized body first. The bound is a
  `max_body` parameter so it is testable without a gigabyte-sized fixture.
- Tests: `an_oversized_protected_value_is_refused_rather_than_decrypted`,
  `a_protected_value_at_the_ceiling_is_not_refused`,
  `a_row_whose_rewrite_outgrows_its_frame_is_refused_while_it_is_built`,
  `hex_text_form_matches_the_representation_it_replaced`.

The ceiling is a constant rather than a config knob; making it configurable is
filed separately.
<!-- SECTION:NOTES:END -->
