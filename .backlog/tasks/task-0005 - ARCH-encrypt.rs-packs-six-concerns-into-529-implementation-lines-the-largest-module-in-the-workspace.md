---
id: TASK-0005
title: >-
  ARCH: encrypt.rs packs six concerns into 529 implementation lines, the largest
  module in the workspace
status: Done
assignee: []
created_date: '2026-08-11 20:40'
updated_date: '2026-08-18 20:39'
labels:
  - architecture
  - encrypt-path
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt.rs` (851 lines: 529 implementation, 321 tests from `#[cfg(test)]` at line 530)

**What**: The module is the workspace's largest by implementation size — `session.rs` is next at 474 lines *including* its tests — and it holds six separable concerns in one flat file:

| Lines | Concern |
|---|---|
| 27-65 | `WriteCatalog` — table/column to transform lookup, identifier normalization |
| 81-292 | `QueryRewriter` — statement dispatch across INSERT / UPDATE / SELECT / DELETE / COPY |
| 317-373 | `TableScope` / `ScopedTable` — alias resolution for WHERE clauses |
| 374-451 | WHERE equality rewriting and blind-index prefix construction |
| 452-515 | Expression-level sealing: cast unwrapping, literal decoding, placeholder capture |
| 519-529 | `RewriteOutcome` — rewritten SQL plus deferred Bind-time param actions |

**Why it matters**: This is the file where a mistake silently writes plaintext to disk — every path in [[task-0001]] lives here. Six concerns in one namespace means the WHERE-scope logic and the seal logic can reach each other freely, and reviewers of a one-line change have to hold all of it at once. The natural seam is clean: catalog, statement rewriting, scope resolution, and expression sealing have almost no shared state beyond `ParamTransforms`.

This is a readability and reviewability concern, not a correctness one — hence low priority. It is worth doing *before* the strict-mode work in [[task-0001]], which adds a branch to every one of the six passthrough sites and will make the file meaningfully larger.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 encrypt.rs is split along the concern boundaries above, with the entry point staying thin
- [x] #2 Tests move alongside the code they cover rather than staying in one 321-line block
- [x] #3 No public API change to QueryRewriter — session.rs is untouched by the split
- [x] #4 make check stays green and the e2e matrix still passes
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Split on refactor/task-0005-split-encrypt into seven modules: catalog, scope, seal, settings, array, lexer, unprotected. encrypt.rs 6497 -> 4530 lines; implementation half 3600 -> 1989. Tests moved with the code they cover (array codec proptests, lexer range proptests, unprotected wording tests); a genuinely shared helper is exported from the module that owns it rather than duplicated. AC #4: ops verify 7/7 and 348 workspace tests, unchanged in count. The task described the file at 851 lines and named six seams; it had grown 7.6x since filing, so the seams were re-derived from the current item map.
<!-- SECTION:NOTES:END -->
