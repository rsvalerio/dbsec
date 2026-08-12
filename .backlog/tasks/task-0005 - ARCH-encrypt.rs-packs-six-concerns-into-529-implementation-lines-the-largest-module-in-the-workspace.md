---
id: TASK-0005
title: >-
  ARCH: encrypt.rs packs six concerns into 529 implementation lines, the largest
  module in the workspace
status: Triage
assignee: []
created_date: '2026-08-11 20:40'
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
- [ ] #1 encrypt.rs is split along the concern boundaries above, with the entry point staying thin
- [ ] #2 Tests move alongside the code they cover rather than staying in one 321-line block
- [ ] #3 No public API change to QueryRewriter — session.rs is untouched by the split
- [ ] #4 make check stays green and the e2e matrix still passes
<!-- AC:END -->
