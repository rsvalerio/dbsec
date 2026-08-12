---
id: TASK-0003
title: >-
  Deterministic keys (blind index, FPE, token) have no rotation or re-index path
  — a leak is unrecoverable
status: Done
assignee:
  - TASK-0052
created_date: '2026-08-11 20:40'
updated_date: '2026-08-12 16:10'
labels:
  - security
  - keys
  - operability
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/vault.rs:10-12`, `crates/core/src/keys.rs:22-23`

**What**: Both `KeySource` implementations treat deterministic keys as permanent. `VaultKeySource` stores them as plain hex in a single KV secret, minted on first use; the module doc states outright that they "can never rotate without breaking determinism". `FileKeySource` reads them from a static `[index_keys]` table. DEKs, by contrast, rotate freely — a fresh one every startup, addressed by key id.

There is no tooling to change a deterministic key: no re-index command, no dual-key read window, no way to recompute a column's blind indexes under a new key.

**Why it matters**: This is correctly documented as a design consequence, but the *operational* consequence has no answer. If an index key is exposed — a leaked KV secret, a compromised keyfile, an insider copy — the blind index becomes an offline equality/frequency oracle over the whole column, and there is no remediation short of a hand-written migration that decrypts every row and rewrites its index. The same key is what makes FPE and tokens reversible-in-place, so the blast radius spans all three deterministic transforms.

The trade-off is accepted; the missing piece is a documented, tested recovery procedure. Even "here is the migration you must write, and here is why the proxy cannot do it for you" would close the gap.

The cheapest real improvement is a **dual-key read window**: accept indexes computed under the old *or* new key on the read path while a background re-index runs, then drop the old key. That turns an unrecoverable event into a scheduled one.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A key-compromise recovery procedure for deterministic keys is written down in plans/PLAN.md or a runbook
- [x] #2 A decision is recorded on whether the proxy supports a dual-key read window for blind indexes, or leaves re-indexing entirely to the operator
- [ ] #3 If dual-key is adopted: index_key resolution accepts an ordered set of keys on read and uses only the newest on write
- [x] #4 Index keys are versioned in KV rather than stored under one unversioned name, so a rotation is expressible at all
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Resolved in TASK-0052 (wave3).

AC #3 is conditional on adopting a dual-key read window. It was considered and **not** adopted; the decision and its rationale are recorded in `plans/PLAN.md` under "Deterministic key rotation and compromise recovery" (a dual-key window only helps blind index — FPE has no way to tell which key produced a stored value and tokens are irreversible — while adding a disjunction to every searchable query). AC #3 is therefore not applicable rather than outstanding.

Implemented: AC #4 — index keys are versioned in KV (`{path}/index_keys/{name}` holding `current` plus a `version -> key` map) instead of one unversioned shared map, so a rotation is expressible and superseded key material survives it.
Designed/documented only: AC #1 and #2 — the compromise-recovery runbook (revoke, take the column out of search, mint the next version, operator re-index, drop the old version) is written down; the re-index itself remains an operator migration the proxy does not drive.
<!-- SECTION:NOTES:END -->
