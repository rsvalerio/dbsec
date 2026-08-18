---
id: TASK-0131
title: >-
  A config file with no [[column]] entries starts a plaintext relay with only an
  INFO line
status: To Do
assignee:
  - TASK-0142
created_date: '2026-08-17 20:31'
updated_date: '2026-08-18 10:00'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/main.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/main.rs` (`serve`, the "dbsec listening" INFO line)

**What**: TASK-0120 closed the *missing config file* half of the fail-open startup: with no path and no `dbsec.toml` the proxy now refuses to start unless `--plain-relay` is passed, and that opt-in logs a WARN saying the process is relaying in plaintext. A config file that exists but configures no `[[column]]` reaches exactly the same state — no encryption, no column protection — and gets no warning at all: the only evidence is `protected_columns=0` inside the `dbsec listening` INFO line, which is what TASK-0088 called insufficient in the first place.

**Why it matters**: a config whose `[[column]]` block was lost to a bad merge, a templating mistake, or an environment-specific overlay is a more likely production shape than a missing file, and it is the one the fail-closed startup does not cover. The two cases should read the same way in the log.

**Fix shape**: emit the same WARN when a loaded config resolves no protected columns; decide deliberately whether a deployment that means it should have to say so (a config-level equivalent of `--plain-relay`) or whether the warning is enough.

**Origin**: discovered during TASK-0120 while fixing TASK-0088.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A config that resolves no protected columns is reported at WARN, not only as a field inside the INFO listening line
- [ ] #2 The no-config plain-relay case and the no-columns config case are consistent with each other
- [ ] #3 A test covers the warning for a config with no [[column]] entries
<!-- AC:END -->
