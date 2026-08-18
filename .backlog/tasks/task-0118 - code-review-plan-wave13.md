---
id: TASK-0118
title: code-review-plan-wave13
status: In Progress
assignee:
  - code-review-wave
created_date: '2026-08-17 20:02'
updated_date: '2026-08-17 20:47'
labels:
  - code-review-wave
dependencies:
  - TASK-0082
  - TASK-0093
  - TASK-0094
  - TASK-0095
  - TASK-0097
  - TASK-0101
modified_files:
  - crates/core/src/envelope.rs
  - crates/core/src/keys.rs
  - crates/core/src/transform.rs
  - crates/proxy/src/columns.rs
  - crates/proxy/src/vault.rs
  - Cargo.toml
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Crypto core: envelope binding, nonce safety, and key-material hygiene
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Overlaps: TASK-0119 wave14 (crates/proxy/src/vault.rs); TASK-0126 wave21 (crates/core/src/envelope.rs, crates/proxy/src/vault.rs)

Branch: code-review/TASK-0118

PARKED (merged, not closed). All four commits landed on main by fast-forward: e89b478, 8beb7c8, 745b590, 9fbb6c8, plus ecb36fe fixing integration fallout (a test that landed on main mid-flight used the pre-context `envelope::encrypt` signature).

Members: TASK-0093, TASK-0094, TASK-0095, TASK-0097, TASK-0101 all Done. TASK-0082 remains In Progress: its AC #2 asks for both cross-column *and* cross-row relocation to fail authentication, and only the cross-column/cross-table half is implementable at this layer — neither data path knows a row's identity. The row half is filed as TASK-0127 (Triage) and documented as a caveat rather than left implicit. The wave parent therefore stays non-done.

Pre-merge `ops verify`: clean. Integration `ops verify`: failed once on the mid-flight test above, fixed on the branch, then clean. `ops verify qa`'s `--ignored` gate fails without a Docker Postgres, identically on main before the wave.

Also filed: TASK-0133 (Triage) — the GHASH authentication subkey inside `Aes256Gcm` is still freed intact when a `Cipher` drops, since `ghash`/`polyval` would need to be added as direct dependencies purely for feature unification.

The worktree ../.wave-TASK-0118 and branch code-review/TASK-0118 are left in place per the parked-wave rule; both are clean and fully merged into main.
<!-- SECTION:NOTES:END -->
