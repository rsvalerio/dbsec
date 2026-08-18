---
id: TASK-0110
title: >-
  Identifier matching diverges from PostgreSQL folding, so non-ASCII or
  over-63-byte protected names can be missed by the write path
status: Done
assignee:
  - TASK-0122
created_date: '2026-08-14 18:16'
updated_date: '2026-08-18 09:34'
labels:
  - security-review
  - security
  - sql-rewrite
  - config
dependencies: []
modified_files:
  - crates/proxy/src/encrypt.rs
  - crates/proxy/src/config.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs:167` (`normalize`) vs config names used verbatim (`columns.rs:140-144`, `config.rs:469 schema_and_table`); no normalization in `Config::validate` (`config.rs:615`).

**What**: the write path matches a SQL identifier by `normalize(ident) == config_name`, where `normalize` lowercases unquoted idents with Rust `str::to_lowercase()` and never truncates, while config names are compared verbatim and never validated. Rust's `to_lowercase()` does full Unicode case-folding (`Ä`→`ä`, Kelvin sign `K` U+212A→`k`), whereas PostgreSQL under a UTF-8 server encoding folds only ASCII in unquoted identifiers (leaving multibyte chars unchanged) and truncates every identifier to 63 bytes (`NAMEDATALEN-1`). Verified empirically that Rust folds these characters and never truncates.

**Why it matters**: the two folders disagree for (a) protected tables/columns named with non-ASCII letters on UTF-8 databases and (b) names ≥ 63 bytes — a client SQL reference PostgreSQL resolves to the protected column can normalize, in the proxy, to a string that does not match the catalog, so the write is treated as unprotected (silent plaintext at rest under the default `warn`). The pure uppercase-in-config case is already caught at boot — `resolve.rs`'s catalog lookup (`attname = $3`) uses the verbatim name and fails startup with `ColumnNotFound` — which is why this is Low rather than Medium; the residual is the non-ASCII / long-identifier runtime divergence and the general fragility of two independently-drifting name paths.

**Fix shape**: normalize configured identifiers with PostgreSQL's actual folding rules (ASCII-only downcase for unquoted names, 63-byte truncation) at config-validation time, and share one folding function between the write-path matcher and the config side so they cannot drift; reject or warn on configured names that are not already in folded form.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A single folding function (ASCII-only downcase, 63-byte truncation) is applied to both config names and SQL identifiers
- [x] #2 Config validation rejects or warns on identifiers that PostgreSQL would fold differently than stored
- [x] #3 Tests cover a non-ASCII-named protected column and a ≥63-byte name
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in wave TASK-0122 (branch code-review/TASK-0122). One folding function, config::fold_identifier (ASCII-only downcase for unquoted names, 63-byte clip on a character boundary, quoted names unfolded), is now the single implementation: encrypt::normalize delegates to it and Config::validate checks the configured [[column]] names against it. Validation errors on any schema/table/column name longer than MAX_IDENTIFIER_BYTES (no catalog row can carry it) and warns when a name is not already in folded form (only a double-quoted SQL reference will match). Tests: config::tests::identifiers_fold_the_way_postgres_folds_them, over_long_identifiers_are_rejected, names_outside_the_folded_form_still_validate; encrypt::tests::a_non_ascii_column_name_is_folded_the_way_postgres_folds_it, an_over_long_identifier_matches_the_name_postgres_truncated_it_to.
<!-- SECTION:NOTES:END -->
