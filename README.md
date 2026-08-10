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
make help     # all targets
make check    # QA gates via `ops verify qa` (fmt, clippy, check, test)
make deny     # license/advisory audit
```

CI and release run through [forge](https://github.com/rsvalerio/forge) reusable
workflows; lint configs (`deny.toml`, `clippy.toml`, `rustfmt.toml`) are copies
of forge's canonical versions.
