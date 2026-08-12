---
id: TASK-0041
title: >-
  ERR-11: serve() restates a config invariant with unreachable! and expect
  instead of encoding it in the type
status: To Do
assignee:
  - TASK-0056
created_date: '2026-08-11 19:36'
updated_date: '2026-08-11 22:42'
labels:
  - code-review-rust
  - error-handling
dependencies: []
modified_files:
  - crates/proxy/src/main.rs
  - crates/proxy/src/config.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/main.rs:114-123`

**What**: `serve()` reads two config invariants back out with panicking macros:

```rust
let keys: Arc<dyn dbsec_core::keys::KeySource> = match (&config.keys_file, &config.vault) {
    (Some(keys_file), None) => Arc::new(FileKeySource::load(keys_file)?),
    (None, Some(vault_config)) => Arc::new(vault::VaultKeySource::connect(vault_config).await?),
    _ => unreachable!("validated: columns require exactly one key source"),
};
let protected = columns::build(&config, &keys);
let dsn = config.control_dsn.as_deref().expect("validated: columns require control_dsn");
```

Both invariants are real, but they are enforced in `Config::validate` (`config.rs:199-245`) — a different module, ~80 lines away, on a private method that only `Config::load` calls. Nothing in the type system connects the two. `Config::default()` (`config.rs:175-187`) constructs a value without validating it, and so does any future programmatic or test construction; today the empty `columns` vector happens to short-circuit before these lines, which is why the panics are unreachable, but that is a property of the current control flow rather than of the data.

**Why it matters**: Per ERR-11, `unreachable!` is for conditions unreachable unless the code itself is wrong — which this is — but the rule's preferred fix applies squarely here: make the state unrepresentable rather than assert it. `validate` already does the work of proving exactly one key source and a present `control_dsn`; it just throws the proof away and hands back the same loosely-typed `Config`. Having it produce a resolved value instead — `enum KeySourceConfig { File(PathBuf), Vault(VaultConfig) }` plus a non-optional DSN on a `ValidatedConfig` — deletes both panics and moves the guarantee to where a reader of `serve()` can see it. As written, the two sites are a standing invitation for a later refactor of `validate` to silently turn a config mistake into a process abort on a code path that has already bound its listener.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Validation produces a type in which exactly one key source and a present control_dsn are structurally guaranteed, rather than re-checked at the use site
- [ ] #2 serve() constructs the key source and reads the DSN with no unreachable! and no expect
- [ ] #3 Config::default() cannot produce a value that reaches the key-source selection in an invalid state
<!-- AC:END -->
