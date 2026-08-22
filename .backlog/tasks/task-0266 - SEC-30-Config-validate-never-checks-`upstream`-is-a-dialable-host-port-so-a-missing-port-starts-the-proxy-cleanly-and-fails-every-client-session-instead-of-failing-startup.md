---
id: TASK-0266
title: >-
  SEC-30: Config::validate never checks `upstream` is a dialable host:port, so a
  missing port starts the proxy cleanly and fails every client session instead
  of failing startup
status: Triage
assignee: []
created_date: '2026-08-22 00:38'
labels:
  - code-review-rust
  - security
dependencies: []
modified_files:
  - crates/proxy/src/config.rs
  - crates/proxy/src/main.rs
  - crates/proxy/src/tls.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/config.rs:580`

**What**: `Config::validate` (crates/proxy/src/config.rs:580-647) checks timeouts, limits, file modes, the vault section and the control DSN but never touches `upstream` (config.rs:308-310, a bare `String`). `listen` is validated implicitly because `serve` binds it at startup (main.rs:668-670); `upstream` is first used by `TcpStream::connect(upstream_addr)` in session.rs:416 — i.e. only once a client has connected — and by `upstream_host` in tls.rs:141 to derive the TLS verification name. A value like `upstream = "db.internal"` (no port) or an unparsable address passes validation, logs `dbsec listening upstream=db.internal` (main.rs:671-682), resolves columns over the *control* DSN successfully, and then every session fails with an `Io`/`ConnectTimeout` warning.

**Why it matters**: The proxy otherwise fails fast on every misconfiguration; this is the one address an operator can mistype and learn about only from per-session WARN lines after a deploy that looked healthy. With `[tls.upstream]` and no `hostname`, `upstream_host` also silently derives a wrong SNI/verification name from the malformed string (e.g. `::1` without brackets yields `::`).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `Config::validate` refuses an `upstream` that does not parse as `host:port` / `[v6]:port` with an `InvalidConfig` naming the field
- [ ] #2 A test pins that `upstream = "::1"`-style input is refused rather than verified against `::` when `[tls.upstream]` has no `hostname`
- [ ] #3 A test asserts that a config with `upstream = "db.internal"` (no port) is rejected at load time
<!-- AC:END -->
