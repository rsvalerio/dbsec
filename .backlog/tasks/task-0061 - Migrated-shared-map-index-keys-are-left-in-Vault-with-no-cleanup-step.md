---
id: TASK-0061
title: Migrated shared-map index keys are left in Vault with no cleanup step
status: To Do
assignee:
  - TASK-0065
created_date: '2026-08-12 16:14'
updated_date: '2026-08-12 18:42'
labels:
  - code-review-rust
  - security
  - vault
  - operability
dependencies: []
modified_files:
  - crates/proxy/src/vault.rs
  - plans/PLAN.md
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/vault.rs` (`adopt_legacy_index_key`)

**What**: TASK-0052 moved deterministic index keys from one shared map at `{path}/index_keys` to one versioned secret per name at `{path}/index_keys/{name}`. A name still found in the old shared map is copied into its own secret and used from there. The old map is never deleted, and nothing reports that a migration happened beyond a single `INFO migrated index key out of the shared-map layout`.

**Why it matters**: The same key material now lives at two paths indefinitely. That doubles the blast radius of the exposure described in [[task-0003]] — a policy granting read on the old path still yields keys that are live at the new one — and the copy is invisible to anyone auditing `{path}/index_keys/*`. It also leaves an ambiguous state: a future reader has no way to tell whether the shared map is stale residue or a still-authoritative source, and the current code will silently prefer the per-name secret while the map keeps whatever it had.

Deliberately out of scope for TASK-0052: deleting key material as a side effect of a read path is not something the proxy should do unprompted, and the destination write is not confirmed durable at that point.

**What is left**: decide whether migration is a proxy behaviour or an operator step. Either (a) document the cleanup in the `plans/PLAN.md` rotation section — verify every name migrated, then delete the shared secret and its version history — or (b) add an explicit one-shot subcommand that migrates and cleans up under operator control, leaving the read path to migrate-and-warn only.

**Origin**: discovered during TASK-0052 while fixing TASK-0007.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A documented or automated path removes the shared-map secret once every name is migrated
- [ ] #2 The migration is observable — an operator can tell which names came from the legacy layout
<!-- AC:END -->
