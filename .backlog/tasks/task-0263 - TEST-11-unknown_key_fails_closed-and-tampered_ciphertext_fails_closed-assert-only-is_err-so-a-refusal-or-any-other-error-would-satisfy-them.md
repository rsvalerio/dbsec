---
id: TASK-0263
title: >-
  TEST-11: unknown_key_fails_closed and tampered_ciphertext_fails_closed assert
  only is_err(), so a refusal or any other error would satisfy them
status: Triage
assignee: []
created_date: '2026-08-22 00:38'
labels:
  - code-review-rust
  - test
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:2324`

**What**: `unknown_key_fails_closed` (rows.rs:2324-2334) and `tampered_ciphertext_fails_closed` (2874-2885) end with `assert!(decryptor.on_frame(b'D', &row).is_err())`. The module's contract is specifically that crypto failures are *fatal* (`Err`) and not refusals (`Ok(RefuseAndClose)`), and that an unknown key id surfaces as `Error::Wire(CoreError::UnknownKey(_))` while a tampered body surfaces as `Error::Wire(CoreError::Decrypt)`; neither test pins the variant, unlike `a_crypto_failure_with_no_row_key_is_not_reported_as_a_relocation` (2517-2531) which does.

**Why it matters**: A change that mis-routes a decrypt failure into `is_refusal`, or that maps UnknownKey onto Decrypt, keeps both tests green even though the distinction is what decides whether the client gets an ErrorResponse and whether the operator can tell key rotation from tampering.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Both tests match the exact `Error` variant (`UnknownKey` / `Decrypt`) and assert `!is_refusal(&error)`
- [ ] #2 Failure messages print the actual error
<!-- AC:END -->
