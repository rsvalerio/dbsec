---
id: TASK-0264
title: >-
  ARCH-1: rows.rs is 3,042 lines, and ~370 lines of its test module exercise
  only the write path (QueryRewriter) without ever constructing a RowDecryptor
status: Triage
assignee: []
created_date: '2026-08-22 00:38'
labels:
  - code-review-rust
  - architecture
dependencies: []
modified_files:
  - crates/proxy/src/rows.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/rows.rs:1933`

**What**: rows.rs is 1,178 production lines plus an 1,864-line `pub mod tests`. Inside the test module, `an_upsert_binds_its_conflict_action_to_the_row_it_conflicts_on` (1939), `an_upsert_that_cannot_name_its_conflicting_row_is_refused` (1966), `excluded_is_re_stored_only_where_the_conflicting_row_shares_the_key` (1988), `an_update_from_binds_the_target_relations_row_key_not_the_joined_ones` (2015), `an_unqualified_row_key_is_refused_once_the_statement_joins` (2041), `an_update_that_also_assigns_the_row_key_is_refused` (2055), `every_site_that_cannot_name_the_row_reports_itself_in_both_modes` (2084) and `an_unusable_row_key_parameter_refuses_the_statement_not_the_session` (2184) drive `crate::encrypt::QueryRewriter` only, bind the returned `RowDecryptor` to `_d`/`_decryptor`, and assert on sealed literals or Bind refusals — they are write-path tests that landed here because `row_bound_session` is the fixture that wires a row key on both sides. The same is true of the helpers `write`, `sealed_literals`, `key_of`, `bind_params` (1899-2175). The production half also mixes four concerns: the resolution snapshot (`Resolved`, `Described`, 167-370), the process-wide `RowContext` (372-471), the per-session frame state machine (`RowDecryptor::inspect`, 546-826), and row-key canonicalisation/attribution helpers (1017-1147).

**Why it matters**: Someone changing the write path's row-key binding has to know to look in rows.rs for its tests, and a reader of the read path scrolls through 3,000 lines to find the decryptor. The precedent is TASK-0188 (Done) which moved the end-to-end tests out of encrypt/mod.rs for the same reason.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Write-path-only tests and their helpers move to the encrypt module's test tree (or a `tests/row_binding.rs` integration test), with the shared `row_bound_session` fixture exposed from one place
- [ ] #2 Consider splitting rows.rs into `rows/resolved.rs` (Resolved/Described/RowKeyRef) and `rows/rowkey.rs` (distinct_slots/RowKeyOnce/read_row_key/attribute_open_failure), leaving RowContext/RowDecryptor in rows.rs
- [ ] #3 No file under crates/proxy/src exceeds ~1,500 lines including tests
<!-- AC:END -->
