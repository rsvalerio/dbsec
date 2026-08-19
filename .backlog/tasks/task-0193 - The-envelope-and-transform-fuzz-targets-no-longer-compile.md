---
id: TASK-0193
title: The envelope and transform fuzz targets no longer compile
status: Triage
assignee: []
created_date: '2026-08-19 20:00'
labels:
  - fuzz
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
cargo check --manifest-path fuzz/Cargo.toml fails with four errors on fuzz_targets/envelope.rs and fuzz_targets/transform.rs. Both call APIs that have since changed shape:

- envelope.rs passes a &CellContext as the second argument of the free function
  envelope::decrypt(key, binding, data), which has taken a &Binding since the column
  binding landed
- transform.rs has three stale one-argument open(stored) calls — on EncryptTransform,
  FpeTransform and TokenTransform — each of which now takes (stored, row)

Pre-existing, not caused by the TASK-0192 refactor — confirmed by checking out HEAD and reproducing the same four errors. It went unnoticed because fuzz/ is excluded from the workspace, so neither cargo check --workspace nor the QA gates ever build it; only make fuzz does, and that is not in CI.

Two things to fix: the targets themselves, and the reason nobody noticed. A cargo check over fuzz/ belongs in the QA gates even though the fuzzing itself does not — the targets are the only coverage the frame parser and the read path have over arbitrary bytes, and a target that does not compile is coverage silently at zero.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 cargo check --manifest-path fuzz/Cargo.toml is clean
- [ ] #2 All three fuzz targets run again under make fuzz
- [ ] #3 A compile check over fuzz/ runs in CI so a stale target fails the build
<!-- AC:END -->
