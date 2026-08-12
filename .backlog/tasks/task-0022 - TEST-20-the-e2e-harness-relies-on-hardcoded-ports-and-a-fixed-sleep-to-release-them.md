---
id: TASK-0022
title: >-
  TEST-20: the e2e harness relies on hardcoded ports and a fixed sleep to
  release them
status: Done
assignee:
  - TASK-0057
created_date: '2026-08-11 19:16'
updated_date: '2026-08-12 10:42'
labels:
  - code-review-rust
  - tests
  - e2e
dependencies: []
modified_files:
  - crates/proxy/tests/common/mod.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/tests/common/mod.rs:20-24`, `crates/proxy/tests/common/mod.rs:105-113`, `crates/proxy/tests/common/mod.rs:184-195`

**What**: Two related timing assumptions in the shared e2e harness:

1. **Fixed ports.** `PORT_TOKIO_POSTGRES = 16432` through `PORT_VAULT = 16435` are compile-time constants, one per test binary. The comment explains the intent — the suites must not fight over one port — and within this repo they do not. What they can collide with is anything else on the machine: a developer's own service, a second checkout of the repo, two CI jobs on the same runner, or a previous run's proxy that outlived its `Drop`.

2. **A sleep standing in for a sync point.** `Proxy::shutdown` kills the child, reaps it, then sleeps a flat 100ms "so the next proxy on the same port does not inherit this one's listener". That is a guess about how fast the kernel releases the listening socket, not a check. `e2e_vault.rs` depends on it directly — it shuts down the first proxy and immediately starts a second on the same port. Under a loaded CI runner the 100ms can be short, and the failure surfaces as the *readiness loop of the second proxy connecting to the first proxy's dying socket*, which is a confusing failure rather than an obvious one.

The readiness loop in `spawn_with_config` (100 attempts x 100ms) is a legitimate poll and not the concern here — it has a real condition to test. The `shutdown` sleep has none.

**Why it matters**: Low severity — these suites are `#[ignore]`d and run under `make e2e`, so the blast radius is a confusing red CI run rather than a shipped bug. It is worth fixing because flaky infrastructure tests get muted, and these are the only tests that exercise the real binary end to end. The shutdown sleep can become a poll for the port to actually refuse connections; the ports can at minimum be overridable by environment variable so a second checkout or a parallel CI job can move them.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Proxy::shutdown waits on an observable condition (the port refusing connections) rather than a fixed sleep, with a bounded deadline and a clear panic message on timeout
- [x] #2 The listen ports are overridable via environment variable so parallel checkouts or CI jobs can avoid a collision
- [x] #3 A port already in use produces a diagnostic naming the port rather than a readiness-loop timeout
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
`crates/proxy/tests/common/mod.rs`:

- `Proxy` now carries its port, and `shutdown` polls `TcpStream::connect` until the port refuses connections, bounded by `PORT_RELEASE_TIMEOUT` (10s) with a panic naming the port and the elapsed budget. The flat 100ms sleep is gone.
- The four `PORT_*` constants became `port_tokio_postgres()` / `port_sqlx()` / `port_psycopg()` / `port_vault()`, each an offset into a block whose base is `DBSEC_E2E_PORT_BASE` (default `DEFAULT_PORT_BASE = 16432`). A bad value panics naming the variable rather than silently falling back. All four suites updated.
- `spawn_with_config` pre-flight binds the port before spawning and panics naming the port when it is taken, pointing at `DBSEC_E2E_PORT_BASE`. Without it an occupied port makes the readiness loop succeed against *another* process's listener and the failure surfaces much later as an unrelated protocol error.
- `README.md` documents `DBSEC_E2E_PORT_BASE`.

Known residual: the pre-flight bind is a TOCTOU check — the port is released before the child binds it. That is accepted for a test harness; the alternative (bind to port 0, per TEST-20's canonical advice) is not available because the proxy takes its listen address from a config file written before the process starts.

Not verified by running the suites: they are `#[ignore]`d and need docker (`make e2e` / `make e2e-vault`), which is not available in this environment. They compile under `cargo build --workspace --all-features --all-targets` and lint clean under `-D warnings`.
<!-- SECTION:NOTES:END -->
