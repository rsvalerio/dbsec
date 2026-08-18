---
id: TASK-0131
title: >-
  A config file with no [[column]] entries starts a plaintext relay with only an
  INFO line
status: Done
assignee:
  - TASK-0142
created_date: '2026-08-17 20:31'
updated_date: '2026-08-18 10:57'
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
- [x] #1 A config that resolves no protected columns is reported at WARN, not only as a field inside the INFO listening line
- [x] #2 The no-config plain-relay case and the no-columns config case are consistent with each other
- [x] #3 A test covers the warning for a config with no [[column]] entries
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0142. The warning is now attached to the *state* rather than to the route: `load_config` resolves the config (explicit path, discovered dbsec.toml, or built-in defaults under --plain-relay) and then emits one WARN — NO_PROTECTION_WARNING — whenever `ValidatedConfig::protected` is None, with a `config` field naming where the config came from ("none (--plain-relay)" for the flag case). That is the same condition the read and write paths switch on, so it cannot drift from what is actually protected. The old, separate plain-relay-only WARN was folded into it, so both routes now log the identical message (AC2). A config-level opt-in was considered and not added: refusing to start on a no-columns config would break the legitimate plain-relay deployment the flag already sanctions, and the decision recorded is that one loud, greppable WARN per startup is the right level. README "Deploying the proxy" documents it. Tests: cli::a_config_with_no_columns_warns_that_nothing_is_protected (WARN level, names the config, still serves) and the extended cli::the_plain_relay_opt_in_falls_back_to_the_default_listen_address, which asserts the same NO_PROTECTION_WARNING constant.
<!-- SECTION:NOTES:END -->
