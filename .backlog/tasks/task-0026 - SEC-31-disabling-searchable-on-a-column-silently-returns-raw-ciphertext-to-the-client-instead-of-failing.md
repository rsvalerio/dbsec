---
id: TASK-0026
title: >-
  SEC-31: disabling searchable on a column silently returns raw ciphertext to
  the client instead of failing
status: To Do
assignee:
  - TASK-0054
created_date: '2026-08-11 19:23'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - security
  - correctness
dependencies: []
modified_files:
  - crates/core/src/transform.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/transform.rs:92-101`

**What**: `EncryptTransform::open` decides how to read a stored value from the *current* config, not from the shape of the bytes:

```rust
let enveloped = match blind_index::split(stored) {
    Some((_index, enveloped)) if self.index_key.is_some() => enveloped,
    _ if envelope::is_enveloped(stored) => stored,
    _ => return Ok(None),
};
```

Rows written while the column was `searchable` are stored as `blind_index (32B) || envelope`. If `index_key` is later set to `None`, the first arm's guard fails. The second arm then checks `is_enveloped(stored)`, which is false — the `DBS1` magic sits at offset 32, not 0. So the function returns `Ok(None)`, and by the passthrough contract documented on `open` the caller hands the stored bytes to the client **unchanged**.

The result is that every row written under the old config now returns 32 bytes of blind index concatenated with an AES-GCM envelope, as if it were a plaintext value. No error, no warning, no log line. Meanwhile `seal` writes new rows as bare envelopes, so the column becomes silently mixed-format and stays that way.

Note the reverse direction is fine: turning `searchable` *on* still reads old bare-envelope rows correctly, because `split` fails and the second arm catches them.

**Why it matters**: The `Ok(None)` passthrough exists for a specific, documented reason — pre-migration plaintext columns (`envelope.rs:7-8`). An index-prefixed ciphertext is not that, and the current code cannot tell the two apart, so a config edit that looks harmless converts a readable column into garbage for every consumer of the proxy. Silent data-shaped corruption is worse than an error here: the client gets bytes that look like a value and will happily store, compare, or display them. It fails open where the rest of the design fails closed, which is the same concern TASK-0001 raises on the write path.

The distinguishing information exists — `split` already told us the value carries an index. The fix is to act on it: when `split` succeeds and `index_key` is `None`, either decrypt the envelope portion anyway (the blind index is only a search token; the envelope is self-describing and authenticated) or return a distinct error naming the config mismatch. Decrypting is the more useful behaviour and makes disabling `searchable` a safe, reversible edit.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A value stored with a blind-index prefix is read correctly (or rejected with a specific error) when index_key is None, rather than passed through as raw bytes
- [ ] #2 A unit test seals with a searchable EncryptTransform and opens with a non-searchable one, asserting the chosen behaviour
- [ ] #3 The passthrough contract on FieldTransform::open documents that it means pre-migration plaintext only, not an unrecognised stored form
<!-- AC:END -->
