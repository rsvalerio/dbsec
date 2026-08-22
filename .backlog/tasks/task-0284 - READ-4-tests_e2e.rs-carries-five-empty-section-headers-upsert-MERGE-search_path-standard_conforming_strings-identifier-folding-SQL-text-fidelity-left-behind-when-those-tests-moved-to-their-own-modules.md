---
id: TASK-0284
title: >-
  READ-4: tests_e2e.rs carries five empty section headers (upsert/MERGE,
  search_path, standard_conforming_strings, identifier folding, SQL text
  fidelity) left behind when those tests moved to their own modules
status: Triage
assignee: []
created_date: '2026-08-22 00:46'
labels:
  - code-review-rust
  - readability
dependencies: []
modified_files:
  - crates/proxy/src/encrypt/tests_e2e.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
**File**: `crates/proxy/src/encrypt/tests_e2e.rs:975`

**What**: crates/proxy/src/encrypt/tests_e2e.rs:975-983 holds four consecutive `// --- <section> ---` banners with no tests between them (`upsert and MERGE`, `search_path`, `standard_conforming_strings`, `identifier folding`), followed by `SQL text fidelity`, whose two tests are lexer tests. The search_path and standard_conforming_strings suites now live in settings.rs (settings.rs:216-564) and identifier folding in catalog.rs (catalog.rs:174-221); the banners are residue of the split the module docs describe (tests_e2e.rs:1-11, test_support.rs:1-8).

**Why it matters**: A reader scanning the file for the search_path or folding tests finds a heading that points at nothing; dead headers also invite new tests to be filed under a banner in the wrong module, undoing the split.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The empty section banners at tests_e2e.rs:975-981 are removed, or replaced by a single comment pointing at the modules that now hold those suites (settings.rs, catalog.rs)
- [ ] #2 Any remaining banner in tests_e2e.rs has at least one test under it
<!-- AC:END -->
