# Changelog
All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

- - -
## v0.6.0 - 2026-08-20
#### Features
- (**core**) add the Protector facade and an embedded sqlx example - (314b417) - Rodrigo Valerio, *Claude Fable 5*
- (**derive**) add #[derive(Protect)] for record-level protection - (036c24b) - Rodrigo Valerio, *Claude Fable 5*
#### Documentation
- (**backlog**) file the record-level derive and close the stale rows in COMPARISON.md - (4eca0f8) - Rodrigo Valerio, *Claude Fable 5*
- (**comparison**) compare dbsec with Acra, CipherStash and peers - (f176727) - Rodrigo Valeri
- describe the nextest gate and record the CONTRIBUTING divergence - (b45553e) - Rodrigo Valerio
- state the design decisions without naming Acra - (3f33db3) - Rodrigo Valeri
#### Tests
- (**core**) pin the typed RowKey constructors to canonical and tighten policy tests - (81057ba) - Rodrigo Valerio, *Claude Fable 5*
#### Build system
- (**test**) run the suite under cargo-nextest - (7f39623) - Rodrigo Valerio
#### Continuous Integration
- move the test job to nextest and off the shared cargo test - (d630ce8) - Rodrigo Valerio
#### Refactoring
- (**core**) move the column policy model into dbsec-core - (e265b2f) - Rodrigo Valerio, *Claude Fable 5*
- (**core**) move the wire codec out and the naming logic in - (4bc80f5) - Rodrigo Valeri
- (**rowkey**) decode wire format codes at the proxy, not in the library - (07774b8) - Rodrigo Valeri
#### Miscellaneous Chores
- (**backlog**) scope TASK-0192.08 to the derive and the canonicalization check - (dc4f295) - Rodrigo Valerio, *Claude Fable 5*
- (**backlog**) close TASK-0192.08 - (8002176) - Rodrigo Valerio, *Claude Fable 5*
- (**backlog**) close TASK-0192.05 - (c7d6fc5) - Rodrigo Valerio, *Claude Fable 5*
- (**backlog**) close TASK-0192.03 - (f499b87) - Rodrigo Valerio, *Claude Fable 5*
- (**backlog**) close the first two library tasks and file the fuzz breakage - (f1d3ebc) - Rodrigo Valeri
- (**backlog**) file the dbsec-core reusability refactor - (853fa80) - Rodrigo Valeri

- - -

## v0.5.0 - 2026-08-19
#### Features
- (**envelope**) make a cell-only value in a row-bound column refusable - (1ae82e8) - Rodrigo Valeri
#### Bug Fixes
- (**ci**) compare a forge waiver by what it does, not by how diff spelled it - (86e5702) - Rodrigo Valeri, *Claude Opus 5 (1M context)*
- (**encrypt**) match a row-key reference the way PostgreSQL folds identifiers - (650dd61) - Rodrigo Valeri, *Claude Opus 5 (1M context)*
- (**encrypt**) put a derived table's output columns in the enclosing scope - (cc2141f) - Rodrigo Valeri, *Claude Opus 5 (1M context)*
- (**encrypt**) seal an INSERT cell-only when it cannot name its row - (358c54f) - Rodrigo Valeri, *Claude Opus 5 (1M context)*
- (**encrypt**) report a computed mask-only column as unprotected - (740154e) - Rodrigo Valeri
- (**encrypt**) refuse an unusable row-key Bind parameter, not the session - (b7d72f7) - Rodrigo Valeri
- (**encrypt**) seal assignment lists against the row they actually write - (76de717) - Rodrigo Valeri
- (**portal**) drop the batch marker of the Execute that started the copy - (a8024a8) - Rodrigo Valeri
- (**proxy**) queue a batch marker for the legacy FunctionCall - (eaf2941) - Rodrigo Valeri
- (**proxy**) read a row key in the format its Bind chose, and refuse an ambiguous one - (1ed573e) - Rodrigo Valeri
- (**rowkey**) canonicalise a row key by value, not by its spelling - (a04a1c9) - Rodrigo Valeri
- (**rows**) name the self-join that projects its row key only once - (d33a072) - Rodrigo Valeri, *Claude Opus 5 (1M context)*
- (**rows**) say which read-path failure happened, and to which cell - (8f4ef12) - Rodrigo Valeri
#### Performance Improvements
- (**rows**) canonicalise a row's key once, under the type it resolved as - (e12b1ac) - Rodrigo Valeri
#### Documentation
- (**cli**) reattach the help-outcome comment to its own test - (3e3c59a) - Rodrigo Valeri
- (**readme**) state which types can name a row, and that value binds - (ae53acb) - Rodrigo Valeri
- (**readme**) state the row-binding constraints as on_unprotected sites - (1e5378b) - Rodrigo Valeri
- (**readme**) note that a row-keyed table's key may appear once per result set - (ea2241f) - Rodrigo Valeri
- (**readme**) state the row_key constraints on upserts and key updates - (4c0b9d4) - Rodrigo Valeri
- (**rows**) say what the name-based computed-column backstop cannot catch - (0d06328) - Rodrigo Valeri
- (**unprotected**) say what a missing row key actually costs - (13fca95) - Rodrigo Valeri
- repair the broken intra-doc links and deny them going forward - (377c8d1) - Rodrigo Valeri
#### Tests
- (**cli**) observe the fallback and the closed pipe without racing or hanging - (6c3715c) - Rodrigo Valeri
- (**encrypt**) drive the reassigned-row-key site the exhaustive match now demands - (cedeb5c) - Rodrigo Valeri
- (**encrypt**) pin the refusal cap and truncate on a char boundary - (ad1d200) - Rodrigo Valeri
- (**encrypt**) drive every unprotected site and keep the set honest - (2d0fecd) - Rodrigo Valeri
- (**rows**) drive every row-key-missing site under warn and reject - (41d3152) - Rodrigo Valeri
- give every log-capture test the callsite priming it needs - (df0ddc1) - Rodrigo Valeri, *Claude Opus 5 (1M context)*
#### Continuous Integration
- run cargo doc so the intra-doc-link deny actually fires - (5b3669d) - Rodrigo Valeri, *Claude Opus 5 (1M context)*
#### Refactoring
- (**encrypt**) split the shared fixtures and the end-to-end suite out of mod.rs - (a5df549) - Rodrigo Valeri, *Claude Opus 5 (1M context)*
- (**encrypt**) split the rewriter into frame, statement, query and predicate layers - (a9c45f5) - Rodrigo Valeri
- (**encrypt**) split the text-array element parsers out of decode_text_array - (60a77de) - Rodrigo Valeri
#### Miscellaneous Chores
- (**backlog**) correct the TASK-0190 record and date its claims - (80fd941) - Rodrigo Valeri, *Claude Opus 5 (1M context)*
- (**backlog**) close code-review wave34 - (dfc3dd7) - Rodrigo Valeri
- (**backlog**) close code-review wave37 - (201d5ff) - Rodrigo Valeri
- (**backlog**) close code-review wave35 - (6af9ace) - Rodrigo Valeri
- (**backlog**) close code-review wave33 - (bebd2df) - Rodrigo Valeri
- (**backlog**) close code-review wave29 - (0829331) - Rodrigo Valeri
- (**backlog**) close code-review wave28 - (6c20251) - Rodrigo Valeri
- (**backlog**) close code-review wave30 - (ecdbf4f) - Rodrigo Valeri
- (**backlog**) close code-review wave32 - (be84805) - Rodrigo Valeri
- (**backlog**) close code-review wave27 - (516c1b6) - Rodrigo Valeri
- (**backlog**) close code-review wave31 - (a4eedd5) - Rodrigo Valeri
- (**backlog**) close code-review wave36 - (f1417bf) - Rodrigo Valeri
- (**backlog**) file the formal review of the row-binding and wave work - (e4e9801) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- save backlog tasks - (562289d) - Rodrigo Valerio

- - -

## v0.4.1 - 2026-08-18
#### Bug Fixes
- (**cli**) treat a closed pipe as a successful --help - (ee2a89b) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
#### Refactoring
- (**encrypt**) split scope resolution and value sealing out too - (44b83a1) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**encrypt**) split the five self-contained concerns out of encrypt.rs - (0276775) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
#### Miscellaneous Chores
- (**backlog**) close TASK-0005 - (283308c) - Rodrigo Valerio, *Claude Opus 5 (1M context)*

- - -

## v0.4.0 - 2026-08-18
#### Features
- (**config**) declare a table's row key - (b4b40f4) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**core**) add the DBS3 row-bound envelope format - (425d43a) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**resolve**) resolve declared row keys and canonicalise their values - (ccaf89c) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- bind encrypted values to the row they were written in - (fc3dcd6) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
#### Documentation
- describe row binding and what declaring a row key costs - (a78ced1) - Rodrigo Valerio, *Claude Opus 5 (1M context)*

- - -

## v0.3.0 - 2026-08-18
#### Features
- (**config**) let a deployment set the read path's per-value ceiling - (3c1ec5b) - Rodrigo Valerio
#### Bug Fixes
- (**encrypt**) see every relation a parenthesized join holds and cover COPY reads - (55682d2) - Rodrigo Valerio
- (**proxy**) read both session settings out of the startup packet - (1ca5ccc) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**proxy**) answer --help, warn on a zero-protection startup, log causes - (fb29fc9) - Rodrigo Valerio
- (**session**) bound a client's frames until the backend authenticates it - (e50e696) - Rodrigo Valerio
#### Documentation
- (**crypto**) argue the unbound row half and the unwiped GHASH subkey in place - (5d29159) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**readme**) document --help and the zero-protection startup warning - (6e7a8df) - Rodrigo Valerio
- note that standard_conforming_strings is watched at connect time - (2cc5a16) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- note that a COPY query's predicates are rewritten - (51ae6ca) - Rodrigo Valerio
#### Miscellaneous Chores
- (**backlog**) close waves 22, 24 and 25 and file the help-pipe defect - (fbeb52a) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**backlog**) close the wave 26 input-bounds findings - (93b97d5) - Rodrigo Valerio
- (**backlog**) close the wave 23 session-settings findings - (273cbf9) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**backlog**) triage the wave 13-21 findings into waves 22-26 - (7a48721) - Rodrigo Valerio, *Claude Opus 5 (1M context)*

- - -

## v0.2.0 - 2026-08-18
#### Features
- (**crypto**) bind a ciphertext to its column and tighten key handling - (8beb7c8) - Rodrigo Valerio
- <span style="background-color: #d73a49; color: white; padding: 2px 6px; border-radius: 3px; font-weight: bold; font-size: 0.85em;">BREAKING</span>(**proxy**) fail closed at startup and stop the config leaking secrets - (313bac4) - Rodrigo Valerio
#### Bug Fixes
- (**config**) refuse a plaintext Vault address and a downgradeable control_dsn - (a3f8bfb) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**core**) stop the process-wide key caches panicking on a poisoned lock - (14b4896) - Rodrigo Valerio
- (**encrypt**) flag a query-source COPY TO STDOUT over a protected table - (7be5c2d) - Rodrigo Valerio
- (**encrypt**) cover every relation a predicate can name, and stop refusing the canonical upsert - (e2cc928) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**pgwire**) cap startup packets well below the 1 GiB frame limit - (8638775) - Rodrigo Valerio
- (**proxy**) tie the TLS context to a validated config and keep control causes typed - (4af0f14) - Rodrigo Valerio
- (**proxy**) track the session state and identifier folding the rewrite assumes - (aa3c94f) - Rodrigo Valerio
- (**proxy**) stop a client desyncing, pinning or killing its own session - (0e1c796) - Rodrigo Valerio
- (**rows**) close the fast-path and cached-statement read holes - (5207383) - Rodrigo Valerio
- (**rows**) pass the cell context in the frame-ceiling test's envelope - (ecb36fe) - Rodrigo Valerio
- (**rows**) bound what one DataRow can cost the decrypt path - (febff13) - Rodrigo Valerio
- (**vault**) pin certificate verification instead of inheriting it from the environment - (310345c) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
#### Documentation
- (**envelope**) warn that renaming a bound column invalidates its ciphertexts - (9fbb6c8) - Rodrigo Valerio
- (**readme**) record that every outbound hop is refused in the clear - (e780591) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**vault**) point the capture-guard reference at the helper, not its static - (76bc57c) - Rodrigo Valerio
- record the session-state and identifier assumptions the rewrite relies on - (8520b92) - Rodrigo Valerio
- record what auth passthrough costs in channel binding and GSSENC - (e45eebd) - Rodrigo Valerio
- record the COPY query form and the function-call fast path as sites - (dabaec0) - Rodrigo Valerio
- record the DBS2 migration, the fork constraint and revocation - (745b590) - Rodrigo Valerio
- cover fail-closed startup, config permissions and process hardening - (c5a85b3) - Rodrigo Valerio
#### Tests
- (**core**) check in the proptest seed for the DBS1/DBS2 magic flip - (e325800) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**core**) decide the tamper error by shape, not by byte position - (97756b3) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**encrypt**) count the sealed literal in the escape-string form it now takes - (4a61ada) - Rodrigo Valerio
- (**vault**) serialise the migration test that captures tracing events - (2a0dd08) - Rodrigo Valerio
#### Build system
- (**deps**) add url so a Vault address is parsed before vaultrs unwraps it - (8e9a88c) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**deps**) pull aes with zeroize so the key schedule is wiped on drop - (e89b478) - Rodrigo Valerio
#### Miscellaneous Chores
- (**backlog**) close waves 13-21 and file what they surfaced - (c5232d6) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**backlog**) triage the remaining 34 findings into waves 13-21 - (2bf3fe1) - Rodrigo Valerio

- - -

## v0.1.8 - 2026-08-17
#### Bug Fixes
- close the computed-column read-path bypass - (8746ee2) - Rodrigo Valerio, *Claude Opus 5 (1M context)*

- - -

## v0.1.7 - 2026-08-17
#### Bug Fixes
- (**encrypt**) traverse subqueries in expression positions - (cc1a169) - Rodrigo Valerio, *Claude Opus 5 (1M context)*

- - -

## v0.1.6 - 2026-08-17
#### Bug Fixes
- (**encrypt**) seal row-wise UPDATE SET (a, b) = (x, y) tuple assignment - (e8f3a01) - Rodrigo Valerio, *Claude Opus 5 (1M context)*

- - -

## v0.1.5 - 2026-08-17
#### Bug Fixes
- (**encrypt**) seal every Postgres string-literal syntax, not just '...' - (21be0e4) - Rodrigo Valerio, *Claude Opus 5 (1M context)*

- - -

## v0.1.4 - 2026-08-16
#### Bug Fixes
- (**encrypt**) accept digits in dollar-quote tags, and property-test the split (#8) - (ffa78b7) - Rodrigo Valeri, *Claude Sonnet 4.6*, *Claude Sonnet 4.6*, *Claude Sonnet 4.6*

- - -

## v0.1.3 - 2026-08-16
#### Bug Fixes
- (**encrypt**) signal predicates over protected columns that have no index (#7) - (24a8afc) - Rodrigo Valeri, *Claude Sonnet 4.6*
- (**encrypt**) stop refusing IS NULL / IS NOT NULL on searchable columns - (2e199d0) - Rodrigo Valerio, *Claude Sonnet 4.6*

- - -

## v0.1.2 - 2026-08-16
#### Bug Fixes
- (**portal**) keep a pipelined Close from orphaning its in-flight Execute - (71935b1) - Rodrigo Valerio, *Claude Sonnet 4.6*
#### Miscellaneous Chores
- (**deny**) re-record the ring clarify waiver against the new forge baseline - (6d4e1ae) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- Merge pull request #5 from rsvalerio/fix/task-0113-pipelined-close - (2c4f592) - Rodrigo Valeri

- - -

## v0.1.1 - 2026-08-14
#### Bug Fixes
- (**encrypt**) honour array escapes outside quotes and name every un-indexable array - (4cddea0) - Rodrigo Valerio, *Claude Opus 5*
- (**rows**) end the session on a read-path refusal so the batch rolls back - (8f50756) - Rodrigo Valerio, *Claude Opus 5*
#### Documentation
- record that a read-path refusal closes the connection - (788bb6f) - Rodrigo Valerio, *Claude Opus 5*
#### Miscellaneous Chores
- (**backlog**) file the aggressive-clippy and portal/rewrite findings - (e90af4c) - Rodrigo Valerio, *Claude Sonnet 4.6*
- (**backlog**) file the crates-wide formal review findings - (a1a2ec2) - Rodrigo Valerio, *Claude Fable 5*
- (**backlog**) close the array codec findings - (d61623f) - Rodrigo Valerio, *Claude Opus 5*
- (**backlog**) close the read-path refusal findings - (a71d65d) - Rodrigo Valerio, *Claude Opus 5*
- (**backlog**) file the wave 10 code-review findings for triage - (964b002) - Rodrigo Valerio, *Claude Opus 5*
#### Style
- (**clippy**) apply pedantic/nursery lint fixes - (13d388a) - Rodrigo Valerio, *Claude Sonnet 4.6*
- add the missing trailing newline to CHANGELOG.md - (225c7ad) - Rodrigo Valerio, *Claude Opus 5*

- - -

## v0.1.0 - 2026-08-13
#### Features
- (**core**) enforce a per-DEK AES-GCM invocation budget with cached ciphers - (d77f17a) - Rodrigo Valerio
- (**core**) add FPE and token transforms, mask spec, wire forms and search hooks - (c3202a6) - Rodrigo Valeri
- (**core**) add ciphertext envelope, blind index, key sourcing and PG wire framing - (3c01a87) - Rodrigo Valeri
- (**encrypt**) rewrite = ANY($1) over a searchable column with a Bind-time array codec - (8ed2fd4) - Rodrigo Valerio
- (**pgwire**) expose the field name of a RowDescription - (0011874) - Rodrigo Valerio
- (**proxy**) redact credentials in Debug and refuse loose secret files - (2c375de) - Rodrigo Valerio
- (**proxy**) bound the startup control connection with a deadline - (b014af3) - Rodrigo Valerio
- (**proxy**) refuse statements that cannot be protected - (8d14ae0) - Rodrigo Valerio
- (**proxy**) OpenBao/Vault key source with Transit-wrapped DEKs - (0bc2718) - Rodrigo Valeri
- (**proxy**) per-column transform kinds, read-path masking and searchable equality rewrite - (8987016) - Rodrigo Valeri
- (**proxy**) encrypt protected columns on the write path - (6f72c3e) - Rodrigo Valeri
- (**proxy**) decrypt protected columns on the read path - (6db4560) - Rodrigo Valeri
- (**proxy**) add frame-aware relay with independently-optional TLS on both hops - (203cd21) - Rodrigo Valeri
#### Bug Fixes
- (**core**) zeroize keyfile material and mint keys from the OS CSPRNG - (d12edd2) - Rodrigo Valerio
- (**core**) open index-prefixed rows when a column stops being searchable - (5480dc7) - Rodrigo Valerio
- (**core**) keep the underlying cause on key file and FPE errors - (8a759a8) - Rodrigo Valerio
- (**pgwire**) reject counts and lengths that do not fit the wire - (c9ac358) - Rodrigo Valerio
- (**proxy**) stop expected vault probes from logging at ERROR - (b586be8) - Rodrigo Valerio
- (**proxy**) refuse a downstream TLS key readable beyond its owner - (d3bff04) - Rodrigo Valerio
- (**proxy**) key protected column positions to the portal being executed - (98a574f) - Rodrigo Valerio
- (**proxy**) verify which rustls crypto provider is in force - (2da69cc) - Rodrigo Valerio
- (**proxy**) bound session lifecycle and survive transient accept errors - (742c80f) - Rodrigo Valerio
- (**proxy**) seal cast-wrapped bytea literals - (0fcbc99) - Claude, *Claude Opus 5*
- (**proxy**) keep text-format BYTEA in its hex shape on the read path - (280baf9) - Claude, *Claude Opus 5*
- (**rows**) refuse a result set with an ErrorResponse instead of dropping the connection - (cfc76a9) - Rodrigo Valerio
- (**test**) keep on_unprotected out of the vault key-source table - (a690cbf) - Rodrigo Valerio
- (**vault**) keep the backend cause on key-source failures - (0e66078) - Rodrigo Valerio
- (**vault**) store index keys per name with check-and-set and bound every lookup - (db54936) - Rodrigo Valerio
#### Documentation
- (**core**) record why the GCM nonce keeps thread_rng - (b9b3bfa) - Rodrigo Valerio
- (**plan**) document retiring the shared-map index-key layout - (76d240f) - Rodrigo Valerio
- (**plan**) record the deterministic key rotation and compromise procedure - (ebac923) - Rodrigo Valerio
- (**plan**) mark milestone 10 complete - (53f44c6) - Claude, *Claude Opus 5*
- (**plan**) mark milestones 6-10 done - (e7638c5) - Rodrigo Valeri
- state that on_unprotected governs both paths and that refusals are statement-level - (d138171) - Rodrigo Valerio
- adapt CONTRIBUTING.md to dbsec and record the forge divergence - (49639ad) - Rodrigo Valerio
- describe column re-resolution and the undescribed-row refusal - (4b72b61) - Rodrigo Valerio
- record the on_unprotected decision and its caveats - (c1edaed) - Rodrigo Valerio
- describe the forge drift check and DBSEC_E2E_PORT_BASE - (612a84d) - Rodrigo Valerio
#### Tests
- (**core**) add a seal and open throughput measurement - (41de67e) - Rodrigo Valerio
- (**core**) fuzz and property-test masking and the transform read path - (696257a) - Rodrigo Valerio
- (**e2e**) cover cached prepared statements and a recreated protected table - (fb69bfd) - Rodrigo Valerio
- (**e2e**) cover COPY on a protected table in both modes - (95bdf66) - Rodrigo Valerio
- (**e2e**) poll for port release and make listen ports overridable - (d2a8cbd) - Rodrigo Valerio
- (**e2e**) cover the OpenBao key source against a live server - (981a38a) - Claude, *Claude Opus 5*
- (**e2e**) add sqlx and psycopg driver matrix - (4ee5409) - Claude, *Claude Opus 5*
- (**proxy**) run the dbsec binary as a command - (cd07f92) - Rodrigo Valerio
- (**resolve**) fold the control-connection tests into one test module - (81346af) - Rodrigo Valerio
- (**resolve**) cover the readable and mask filter behind a named helper - (1266f31) - Rodrigo Valerio
- add cargo-fuzz targets and dockerized end-to-end driver suite - (7514040) - Rodrigo Valeri
#### Build system
- (**cargo**) add futures-util as a dev-dependency - (8065640) - Rodrigo Valerio
- (**cargo**) declare workspace lints and inherit tempfile - (64688f6) - Rodrigo Valerio
#### Continuous Integration
- (**forge**) fail the build when copied forge configs drift - (93e03fc) - Rodrigo Valerio
- give each e2e job its own cache key - (05ba01c) - Claude, *Claude Opus 5*
- narrow the e2e trigger to main and pull requests - (29164af) - Claude, *Claude Opus 5*
- run the e2e suites against service containers - (cc35265) - Claude, *Claude Opus 5*
#### Refactoring
- (**proxy**) resolve the key source and control DSN during validation - (4a3e11e) - Rodrigo Valerio
#### Miscellaneous Chores
- (**backlog**) close code-review wave 10 and the fail-closed contract it completes - (f666392) - Rodrigo Valerio, *Claude Opus 5*
- (**backlog**) close code-review wave 9 - (0ca2e0f) - Rodrigo Valerio
- (**backlog**) close code-review wave 11 - (1040f5d) - Rodrigo Valerio
- (**backlog**) close code-review wave 12 - (baf7e47) - Rodrigo Valerio
- (**backlog**) file the read-path refusal shape for triage - (4e61a05) - Rodrigo Valerio
- (**backlog**) close code-review wave 1 - (18f7fce) - Rodrigo Valerio
- (**backlog**) close code-review wave 4 - (f6e9f9e) - Rodrigo Valerio
- (**backlog**) close code-review wave 7 - (5f7fcda) - Rodrigo Valerio
- (**backlog**) record code-review wave 0 - (3f782a4) - Rodrigo Valerio
- (**backlog**) close code-review wave 3 - (05d20b0) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**backlog**) close code-review wave 5 - (5b111ce) - Rodrigo Valerio
- (**backlog**) close code-review wave 6 - (959f1b2) - Rodrigo Valerio
- (**backlog**) close code-review wave 2 - (19dd4c6) - Rodrigo Valerio
- (**backlog**) close code-review wave 8 - (403806a) - Rodrigo Valerio
- (**backlog**) track backlog tasks and code-review waves - (84d5507) - Rodrigo Valerio, *Claude Opus 5 (1M context)*
- (**repo**) scaffold workspace, CI and QA tooling - (179ba77) - Rodrigo Valeri
- add backlog tasks - (289fd0d) - Rodrigo Valerio
#### Style
- (**proxy**) rewrap the control-column resolution call - (3764b85) - Rodrigo Valerio
- (**proxy**) use the imported envelope path in the row tests - (139a804) - Rodrigo Valerio

- - -

Changelog generated by [cocogitto](https://github.com/cocogitto/cocogitto).
