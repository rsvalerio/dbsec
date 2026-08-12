---
id: TASK-0030
title: >-
  ERR-2: Error flattens io, toml and FF1 causes into Strings, so the error chain
  ends at dbsec-core
status: Done
assignee:
  - TASK-0054
created_date: '2026-08-11 19:25'
updated_date: '2026-08-12 11:02'
labels:
  - code-review-rust
  - errors
dependencies: []
modified_files:
  - crates/core/src/lib.rs
  - crates/core/src/keys.rs
  - crates/core/src/transform.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/core/src/lib.rs:26-28`, `crates/core/src/keys.rs:54-57`, `crates/core/src/keys.rs:96-99`, `crates/core/src/transform.rs:146-150`

**What**: Two variants of the public `Error` carry a `String` built by formatting away a real error type:

```rust
#[error("FPE: {0}")]
Fpe(String),
#[error("key source: {0}")]
KeySource(String),
```

Every construction throws away a typed cause:

- `keys.rs:55` — `format!("reading {}: {e}", path.display())` discards a `std::io::Error`, so the caller cannot match on `ErrorKind::NotFound` vs `PermissionDenied`.
- `keys.rs:57` — `format!("parsing {}: {e}", ...)` discards a `toml::de::Error`. Its `Display` includes the line and column, so the message stays useful (ERR-14 is satisfied in text), but the span is no longer machine-readable.
- `keys.rs:97` and `keys.rs:99` — same for the `create_new`/`write_all` io errors in `generate`.
- `transform.rs:150` — `.map_err(|e| Error::Fpe(e.to_string()))` discards the FF1 error type.

Neither variant carries `#[source]`, so `std::error::Error::source()` returns `None` and anything walking the chain — `anyhow`'s `{:#}`, `tracing`'s error field, a future `--verbose` flag — sees one flat line.

**Why it matters**: ERR-2 and ERR-10 exist because `String` payloads are a one-way door: the information is destroyed at construction, so no caller can ever recover it, and the only recourse is substring-matching the message. The concrete cost here is that the proxy cannot distinguish "keyfile is missing" from "keyfile is unreadable" from "keyfile is malformed" — three failures with three different operator actions, all arriving as `Error::KeySource(String)`. That distinction becomes load-bearing the moment TASK-0019 adds a permissions check, which is a fourth case in the same variant.

The fix is structural rather than cosmetic: split into variants that keep their causes, for example `KeyFileRead { path: PathBuf, #[source] source: io::Error }` and `KeyFileParse { path: PathBuf, #[source] source: toml::de::Error }`. `thiserror` already generates the `Display` and `source` impls. Since `Error` is public API, consider adding `#[non_exhaustive]` in the same pass so later variants are not breaking changes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Error::KeySource is replaced by variants that retain the underlying io::Error and toml::de::Error via #[source], with the path as a typed field
- [x] #2 Error::Fpe retains the FF1 error as a source rather than a formatted String
- [x] #3 source() returns the underlying cause for every error originating from a fallible dependency call
- [x] #4 Error is marked #[non_exhaustive], or a comment records why it is not
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
`Error` is now `#[non_exhaustive]` and the file key source's failures keep their
causes:

- `KeyFileRead { path, #[source] io::Error }`, `KeyFileWrite { path, #[source]
  io::Error }` and `KeyFileParse { path, #[source] toml::de::Error }` replace the
  formatted strings in `FileKeySource::load`/`generate`, so "missing" /
  "unreadable" / "malformed" are matchable and the toml span survives.
- `Error::Fpe` carries `fpe::ff1::NumeralStringError` as a `#[from]` source. The
  old `Error::Fpe("invalid FF1 key")` construction is gone: `FF1::new` only
  rejects a radix outside 2..=2^16 and 10 is a constant, so that path is an
  internal invariant (`expect`) rather than an error.
- Tests `missing_keyfile_keeps_the_io_error_as_a_cause` and
  `malformed_keyfile_keeps_the_toml_error_as_a_cause` assert `source()` chains.

`Error::KeySource(String)` is deliberately retained, with a doc comment saying
so: it now covers only backends with no typed cause to keep (malformed key
material in the keyfile, and the Vault/OpenBao source in crates/proxy). Filing
that remaining flattening as its own finding — it lives outside this wave's file
scope and needs a cross-crate decision.
<!-- SECTION:NOTES:END -->
