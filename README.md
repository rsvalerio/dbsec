# dbsec

Transparent PostgreSQL proxy for field-level encryption — a deliberately small
Acra replacement. A library (`dbsec-core`) does the work; the `dbsec` binary is
a thin tokio TCP wrapper around it.

- AES-256-GCM ciphertext envelope with key ids (rotation-friendly), Vault/OpenBao-backed keys
- Searchable encryption via deterministic HMAC blind index
- Storage-free pseudonymization (FF1 FPE + HMAC tokens) and read-path masking
- TLS on both hops (rustls), flat TOML config, PostgreSQL only

Status: scaffold. Roadmap and design in [plans/PLAN.md](plans/PLAN.md).

## Develop

```
make help      # all targets
make check     # QA gates via `ops verify qa` (fmt, clippy, check, test)
make deny      # license/advisory audit
make e2e       # driver matrix through the real binary (needs docker)
make e2e-vault # OpenBao-backed keys against a live dev-mode server (needs docker)
```

Both e2e targets also run in CI (`.github/workflows/e2e.yml`) against service
containers, since the QA gates alone never reach them.

`make e2e` runs the proxy between a dockerized Postgres and tokio-postgres, sqlx
and psycopg 2/3; the Python cases are skipped unless
`pip install 'psycopg[binary]' psycopg2-binary` has run — set
`DBSEC_E2E_STRICT_DRIVERS=1` to make that a failure instead. Both targets reuse
services you already run when `DBSEC_E2E_DSN` / `DBSEC_E2E_VAULT_ADDR` are set,
and start throwaway containers otherwise.

Each suite listens on its own port from a block starting at 16432. Set
`DBSEC_E2E_PORT_BASE` to move the block when something else on the machine — a
second checkout, another CI job on the same runner — already holds it.

CI and release run through [forge](https://github.com/rsvalerio/forge) reusable
workflows; lint configs (`deny.toml`, `clippy.toml`, `rustfmt.toml`) and
`CONTRIBUTING.md` are copies of forge's canonical versions. `make forge-sync`
(also a CI job) diffs them against the forge tag the workflows are pinned to, so
a copy going stale fails the build instead of going unnoticed. Divergence that
is deliberate is recorded as a waiver under `.forge-sync/waivers/`, which pins
the expected diff — a later change on the forge side still fails.
