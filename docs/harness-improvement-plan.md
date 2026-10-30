# Harness improvement plan

Preserve existing target adapters and evidence while reducing the work needed
to translate, integrate and qualify another DOS program. Existing TD3 acceptance
criteria remain unchanged. This is an incremental migration, not a rewrite.

## 1. Reliable capture and comparison

- Make complete state comparison the CLI default; retain explicit partial diagnostics.
- Validate RSP checksums and fragmented reads; buffer QMP messages and handle events.
- Reject reuse of a timed-out QMP channel rather than associating a late reply
  with another operation. Never automatically replay guest execution.
- Record capture inputs before execution and mutable outputs afterward.
- Add reproducing tests before each fix.

Acceptance: negative controls fail, existing generic contracts pass, and
protocol tests cover fragmented/coalesced messages and timeout recovery rules.

## 2. Reusable capture requests

- Introduce a versioned capture-plan file at the existing CLI boundary.
- Resolve paths relative to the plan, validate options before launch, and retain
  the resolved request in evidence. Reuse the existing adapter execution path.
- Record wall time and preserve failure evidence. Keep dry-run read-only.
- Later replace the low-level flag combinations with typed execution operations
  and extract an owned backend session. Migrate one existing TD3 capture before
  changing the PowerShell/WSL launcher.

Acceptance: equivalent CLI and plan inputs produce equivalent adapter commands;
invalid plans cannot start a backend; pre/post evidence survives backend failure.

## 3. Translation and differential workbench

- Export a versioned program index: functions, calls, address spaces, memory
  references, candidate aliases, confidence and evidence identities.
- Generate bounded function work packages and a ledger distinguishing mapped,
  specified, implemented, integrated and validated work.
- Extend bounded original/native experiments with explicit completion/trap
  contracts and filtered ordered writes. Reuse setup only with complete reset.
- Pilot canonical shared storage behind typed accessors in one TD3 scratch
  region before offering a target-neutral compatibility-core template.

Acceptance: migrate an existing TD3 experiment without changing its compared
fields or oracle; detect a known wrong implementation and advance an integrated
boundary. Static coverage never counts as runtime validation.

## 4. Session and evidence consolidation

- Session-owned processes, protocol clients, breakpoints and machine state.
- One artifact writer and immutable run manifest; derive compact summaries
  from it and avoid rehashing sealed immutable artifacts during routine reuse.
- Profile launch, restore, execution, transfer, comparison and finalization.
- Add a synthetic protocol integration suite and a bounded pinned-backend smoke
  test before extracting orchestration from remote_capture.main.

Acceptance: equivalent capture boundaries/artifacts through the migrated path,
owned-process cleanup, useful partial failure reports and measured iteration cost.

## Skill guidance

Document the translation workflow and compact work-package format in a linked
reference. Keep available commands distinct from planned infrastructure. Do not
require agent delegation or exact hardware scheduling unless the task requires it.

## Recorded implementation status

Delivered the phase 1 fixes and the phase 2 capture-plan interface. Extracted RSP
and QMP clients into `remote_protocol.py`, retaining existing imports through
`remote_capture.py`. Updated the skill with translation/integration guidance and
moved detailed capture recipes into a linked reference.

Validation: all 277 tests pass, including protocol fragmentation, timeout reuse,
missing-field rejection, pre/post input identity, plan/CLI equivalence and a real
synthetic adapter subprocess. Skill validation and whitespace checks pass.
No live DOSBox-X capture or native TD3 regression was run for this change.

Remaining: typed operations and owned sessions from phase 2, plus phases 3 and 4.
Next, migrate one existing TD3 capture through a plan and measure its wall-time
breakdown before changing launcher orchestration. The foundation reduces unsafe
results and repeated command construction; emulator throughput gains remain
unmeasured.

## 2026-10-21 workflow audit and next implementation order

See [the workflow audit](workflow-audit-2026-10-21.md) for current code inspection,
fresh CPU calibration/tests, measured iteration costs and scoped findings.
The 277-test result above is historical; it was not reused as fresh verification.

The audit confirms existing cross-target Unicorn reuse and identifies missing
experiment/evidence orchestration. Implement incrementally in this order:

1. Prune ignored publication-audit directories before traversal; make verification
   temp-root selection explicit. Preserve current findings and rejection policy.
2. Share native command receipts and declared dependency preflight with the
   existing evidence layer; migrate one log/time wrapper before a pipeline API.
3. Add optional bounded, filtered ordered RAM-write observations to the existing
   Unicorn runner. Keep default interrupt/I/O rejection and target device models.
4. Add a versioned CPU fixture/experiment contract; migrate an independently
   calibrated case from each of two existing targets without changing its oracle.
5. Generate current evidence/ownership status from explicit dependencies, then
   narrow per-case cache invalidation conservatively. Retain old cache namespaces.
6. Export a versioned Ghidra program index feeding existing progress accounting.

At audit these were planned, not available CLI commands. Current implementation
is recorded below. Detailed acceptance and negative controls are in the audit.
Do not start persistent backend extraction
until profiling identifies capture launch/restore/transfer as the relevant cost;
the latest long integration stage was native replay. No emulator or game code
was changed by the audit, and existing acceptance criteria remain intact.

## Implemented workbench, 2026-10-21

The [workbench contracts](workbench.md) document the delivered interfaces:

- Publication auditing prunes ignored trees before traversal. The reproducing
  traversal test failed before the fix; path/per-file finding order is retained.
- `scripts/run-tests.ps1` scopes and checks writable temp storage. Generic progress
  tests no longer create a target-specific scratch directory.
- `run-plan` and `execution.run_command` provide one-shot logs, tool/input
  identities, dependency preflight, before/after mutation checks, failure receipts
  and stage times. One existing target log/time command was migrated privately.
- Optional bounded ordered RAM writes extend the existing Unicorn runner.
  Alias/overlap/REP/overflow/device negatives pass. Executed-code-page writes
  reject in trace mode because translation retries can repeat pre-write hooks.
- `probe-plan` binds CPU fixtures/references and optional native JSON comparison.
  Its separate CPU cache checks used inputs, support code and engine identities;
  unrelated target tools are excluded. Native comparisons remain uncached.
- `evidence-status` generates JSON/Markdown current ledgers and scoped cache keys
  from declared dependency graphs, preserving results separately from freshness.
- Read-only `program-index` Ghidra export feeds existing progress accounting with
  mapped functions only; reviewed extents and reconstruction credit stay unset.
- The existing skill now prefers qualified replay, names the shipped commands,
  and separates integration/certification without changing accepted criteria.

Fresh final validation: **325 tests run, 324 pass, one hardlink-permission skip**,
14.523 seconds test time / 15.350 seconds process wall time. The earlier audit
suite took 102.455 seconds with 296 tests and temp errors; these are different
cohorts, not a controlled traversal speed benchmark. Skill validation and
whitespace checks pass.

Private migrations preserve old comparisons and records:

- Stellar 7 RNG: all640KiB RAM and16-bit register comparison exact,20 instructions;
  four ordered writes observed. Final command wall0.678s, cached0.535s. The
  unchanged legacy verifier also passes through `run-plan` in0.861s.
- Test Drive 3 angle: same64KiB DS and13-register comparison exact,36 instructions;
  wall0.593s, cached0.438s. Existing native plan JSON comparison passes in0.557s.
- Ghidra12.0.3 compiled/executed the exporter on a fresh synthetic project and
  through the public read-only wrapper. Export imports into progress with one
  mapped function, zero reconstruction and incomplete discovery.
- A two-record current ledger was generated from declared migration dependencies.
  No live original capture or full target acceptance rerun was needed; no target
  game/acceptance code or historical capture/cache manifest was rewritten.

Private execution receipts and verification are under
`.work/improvements/workbench-20261021/`. Target fixture plans are under each
target's `.work/analysis/harness-workbench-migration-20261021/`.

Remaining deliberate limits: dependency completeness/ownership is declared,
not automatically inferred; calibration ancestry still needs target review;
the existing native acceptance cache has not been wholesale migrated; Ghidra
alias inference and verified file extents remain open. Persistent backend
sessions/typed execution operations remain deferred until profiling justifies
them. These are not new game-fidelity claims or a whole-PC Unicorn emulator.

## Configuration and consolidation, 2026-10-30

Delivered the first batch from the later harness audit:

- Run-plan v2 extends the existing receipt layer with named jobs, selected input
  groups, explicit private host profiles/tool prefixes, variable expansion and
  child-only environment removal. Expected failures have separate job results;
  raw execution failures and cache eligibility retain their meaning. V1 and the
  existing native CPU comparison remain compatible.
- Publication auditing can inspect exact Git index blobs or an explicit file
  selection without walking unrelated untracked projects. It rejects selected
  private/generated files, local configuration names, full-text personal/workspace
  paths and absolute JSON host path fields. Public examples contain no host paths;
  actual profiles remain in ignored `.work`. This remains a conservative review
  gate, not a complete secret or proprietary-data classifier.
- `scripts/run_tests.py` owns cross-platform test storage/environment setup;
  both PowerShell entry points delegate. Default remote capture output now goes
  under `.work`. No capture orchestration or game behavior was rewritten.
- The README is 72 lines, with the previous detailed content retained in
  [the usage reference](usage-reference.md). The
  [configuration/publication guide](configuration-and-publication.md) defines the
  new contracts. No new mandatory runtime dependency was added.
- Data-free CI covers Windows/Ubuntu 24.04, a Windows Python 3.8 minimum-version
  job and optional pinned Unicorn tests. Actions are pinned by commit with
  read-only permissions. The hosted workflow has not been dispatched here.
- Linux validation exposed omitted versioned `.so` libraries in probe cache
  identities. A reproducing test failed before the fix; `.so.2` now participates
  in the engine identity and changing it invalidates the cache.

Fresh final local validation with Unicorn 2.1.4: **340 tests, 339 pass and one
hardlink-permission skip on each OS**. Windows Python 3.11 took 18.807s test time /
19.495s process wall time; Ubuntu 24.04 Python 3.12 took 35.710s / 37.137s.
The Windows Python 3.8/3.13 and hosted CI matrix remain to be run by CI.
The public example smoke job passes; 165 selected public files and the current
Git index have no audit findings. Selection is explicit and excludes unreviewed
untracked game trees.

Private named-job migrations replayed the existing qualified Stellar 7 RNG
(20 instructions, all 640KiB RAM and selected registers exact, 0.674s outer wall)
and Test Drive 3 angle (36 instructions, selected 64KiB DS/registers exact, 0.894s).
Original captures, oracles and historical plans were preserved; these are bounded
CPU contracts, not new natural-gameplay claims. Relocation, stale-input rejection,
expected-failure mismatch and child environment isolation have data-free tests.
Evidence, baseline hashes and logs are under
`.work/improvements/harness-consolidation-20261030/`.

Capture orchestration extraction remains a separate change. Do not split the
large driver or replace working target wrappers wholesale merely to reduce line
counts. Migrate demonstrated repetitions through these interfaces incrementally;
profile the actual next slow boundary before adding more orchestration.

## Capture connection ownership, 2026-10-30

The next bounded migration adds `remote_session.RemoteConnections` to the existing
remote driver. It owns one RSP client and the currently open QMP clients. All 20
QMP creation sites retain their existing boundaries; explicit releases close once,
and context exit closes remaining clients even when RSP setup fails after a
paused state load. RSP detach still precedes final QMP cleanup. Cleanup attempts
all clients without masking a primary capture error. Failed QMP handshakes and
RSP socket setup also close their newly acquired socket.

QMP's new instance reader overrides the legacy class-global fallback. The owned
driver uses only its own RSP reader, including disabling fallback before RSP exists;
direct legacy callers retain their API. A timeout still taints the QMP channel,
with no retry or replay. This owns connections, not backend processes, breakpoints
or reusable machine state. Persistent backend sessions remain deferred.

Eleven new tests cover independent captures, early connection failure, cleanup
failure, unchanged successful driver artifacts/order and actual localhost RSP/QMP
traffic. The saved pre-change driver reproduces the paused-load leak while passing
the same successful capture test. AST comparison preserves every controller
function after normalizing only connection ownership/open/release changes.
One source-order assertion was adapted to the new factory spelling; its required
paused-load release ordering is unchanged. A pre-existing QMP test's Python
3.9-only path helper was replaced for the declared Python 3.8 CI cohort.

Fresh full validation with Unicorn: Windows Python 3.11 **351 pass**, 29.068s test
time / 30.520s process wall; Ubuntu 24.04 Python 3.12 **350 pass, one hardlink skip**,
37.616s / 39.142s. The adjusted path-helper cohort passes separately. Hosted CI
and the Python 3.8 matrix have not been run here. **167 explicitly selected public
files and the actual Git index have no publication findings.** Target source and
historical evidence remain unchanged; private logs, baseline hashes and experiments
are under `.work/improvements/capture-ownership-20261030/`.

At that checkpoint, live-backend qualification remained open: a generated-COM smoke test on
Ubuntu 24.04 failed before protocol connection because the existing private
DOSBox-X binary requires unavailable `libavcodec.so.58`. No game data was used,
no original captures were refreshed, no global host configuration was changed,
and only the exact smoke-test process was terminated. Synthetic protocol/driver
passes do not replace this missing emulator check. Qualify a compatible pinned
backend through explicit private configuration before further orchestration
extraction or claims about capture throughput.

## Pre-publication validation, 2026-10-30

The local CI and live-backend gaps above are now resolved at the following scope.
Tests ran against an isolated export of all 167 proposed public files, with its
own Git index and no game data. The real repository index was not changed.

| Host/interpreter | Tests | Expected skips | Process wall |
|---|---:|---:|---:|
| Windows, Python 3.8.20 core | 352 | 29 optional CPU tests | 29.982s |
| Windows, Python 3.13.12 core | 352 | 29 optional CPU tests | 31.708s |
| Ubuntu 24.04, Python 3.13.12 core | 352 | 29 optional CPU tests, one hardlink | 45.125s |
| Windows, Python 3.13.12 with Unicorn 2.1.4 | 352 | 0 | 23.661s |
| Ubuntu 24.04, Python 3.13.12 with Unicorn 2.1.4 | 352 | one hardlink | 51.324s |

All five cohorts pass. The actual Python 3.8 run found eight failures: six test
headers used newer context-manager syntax, one test used `ast.unparse`, and
`socket.timeout` bypassed memory fallback because it was not yet an alias for
`TimeoutError`. The headers retain their newer-interpreter AST; the selector now
compares AST structures; the fallback accepts both timeout classes. A regression
test covers the older socket exception independently of interpreter version.
Actionlint 1.7.12, downloaded from its official release and checksum-verified,
reports no workflow errors. Hosted Actions execution necessarily follows a branch
push; it has not been dispatched or represented as passing here.

Built the locked source and unchanged patch on Ubuntu 24.04, using existing
32-bit SDL2 libraries and privately unpacked matching curses packages. No system
packages, global WSL settings or existing backend binaries were changed. The
profile enables heavy debug/remote servers and excludes optional FFmpeg linkage.
An initial mount failure was isolated to 32-bit `stat` inode overflow: a minimal
probe fails with `EOVERFLOW` using the upstream header order and succeeds with
`-D_FILE_OFFSET_BITS=64` on the compiler command line. The rebuilt binary uses
that flag and `-msse2`; source, patch, compiler/dependency records and binary hash
are retained privately. See the backend README for these host-build requirements.

Live validation uses a generated stationary mode-13h COM program. The reference
driver from before connection ownership and the current driver each load the
same paused full-machine save-state. **All 16 registers, 516 selected RAM bytes,
64,000 indexed pixels, the PGM and 768-byte palette match exactly; all 25 ordered
protocol requests match.** Saving also preserves the seed registers. Reference
and current capture/check wall times are 0.692s and 0.739s; the full smoke takes
4.284s, or 6.486s through a bound named-job receipt. The successful clean configure
and build take 66.020s and 370.711s respectively; these are one-time host build
costs, not capture iteration costs or a capture speedup claim.

Private evidence is under `.work/improvements/prepublish-validation-20261030/`:
`public-*-result.json`, `workflow-lint.json`, `backend-build.json`,
`native-qualified/report.json` and `native-execution/receipt.json`.
Actual host profiles, runtimes, dependency packages and generated DOS/state data
remain ignored. Game sources and historical captures remain untouched. This
qualifies the synthetic save/load/readback and connection boundary; it does not
requalify original campaigns, audio timing or excluded backend features.
