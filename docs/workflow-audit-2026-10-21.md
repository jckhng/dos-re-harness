# DOS reimplementation workflow audit

Audit date: 2026-10-21. Scope: reusable harness and skill improvements, using
Stellar 7 as an integration case and Test Drive 3 as a second existing client.
No game, emulator, acceptance policy or runtime harness code was changed by
this audit. No live original capture or full gameplay replay was needed.

## Assessment

The harness already has useful reusable capture, comparison and CPU-probe
primitives. Unicorn has been used extensively and produced specific recovery
results. The larger remaining gap is managing experiments and integrations:
fixture construction, dependency identities, execution receipts, current status
and deciding which verification tier to run.

Prioritize a small execution/evidence layer and a better CPU experiment interface.
Do not start by replacing DOSBox, building a complete PC inside Unicorn or
moving game-specific simulation, renderer or device policies into the harness.

The original hardware-ancestry work remains legitimate fidelity work. A useful
workflow improvement was giving playable integration and strict certification
separate gates and queues. A component match, code-coverage figure and naturally
retained gameplay route answer different questions.

## What has already improved

| Area | Existing implementation | Benefit and limits |
|---|---|---|
| Capture requests | `capture_plan.py`, `capture-plan`, version 1 plans and dry-run command resolution | Replaces repeated long argument lists while retaining adapter semantics. Still uses opaque adapter options, not typed execution operations. |
| Protocol reliability | `remote_protocol.py`, RSP/QMP tests | Checksums, fragmented/coalesced input, timeout handling and explicit rejection of unsafe channel reuse. Does not justify automatic replay of guest execution. |
| Input/evidence identity | `evidence.py`, `capture_summary.py`, immutable target records | Captures identities before execution, mutable files afterward, failure status and compact summaries. Native build/test/integration wrappers still duplicate these mechanics. |
| Comparison | Strict `diff-state`, streaming trace comparison, indexed frame/palette and wave tools | Missing fields fail by default; explicit diagnostic transforms stay visible. Existing breakpoint write-stream extraction is not a Unicorn memory-write recorder. |
| Recovery accounting | `progress.py` and translation-workflow reference | Separates reconstruction, integration, verification freshness and natural playability. Needs maintained inventories; it cannot discover function extents or infer total completion from filenames. |
| Integration policy | Function-family contracts, persistent owners, explicit unsupported domains, focused regressions | Whole operations now feed retained routes. Exhaustive per-pose probes and repeated full suites are not required before every edit. |
| CPU experiments | Optional pinned Unicorn 2.1.4 and `run_callback` | Reuses original code and private RAM fixtures for bounded deterministic tests, without putting RE tools into the delivered game. |

The old improvement-plan statement that 277 tests passed is historical. Fresh
audit results are recorded below; this audit does not relabel old checks as rerun.

## Unicorn: actual use and evidence

The source inventory counts call sites, not executed cases or correctness:

| Existing client | Files using Unicorn execution | Shared `run_callback` call sites | Direct `emu_start` call sites |
|---|---:|---:|---:|
| Stellar 7 tools | 33 | 36 | 5 |
| Stellar 7 acceptance tests | 1 | 14 | 0 |
| Test Drive 3 tests | 135 | 262 | 0 |

Stellar 7 uses it for RNG, callback/driver logic, object work, clipping, polygon
edges, geometry/projection, raster effects and loader contracts. The five custom
runners show demand for effects and instrumentation beyond the shared API;
they do not by themselves demonstrate incorrect experiments.

A concrete successful use is checkpoint 206: a paired original RNG call was
calibrated against DOSBox, then a recorded 33-call chain helped recover actor and
ground initialization order across a level transition. The port implements the
recovered operations; it does not replace them with a fixed 33-call skip.
The checkpoint also records that seeded radii were another independent issue.

Freshly replaying that qualified single-call fixture through the current shared
runner took **0.480 seconds including Python startup and comparison**. It executed
20 instructions and matched all 640 KiB RAM plus the compared 16-bit registers.
This reuses the independent original capture; it is not a new DOSBox run or a
measurement of Unicorn execution alone.

The shared runner currently provides:

- Fresh CPU and RAM for independent calls; near/far synthetic-return or
  stack-preserving snapshot modes, including repeated stop occurrences.
- Exact segmented stopping, selected register observations, finite instruction
  and wall-time caps, unmapped-memory diagnostics, interrupt and port rejection.
- Final RAM/registers and an execution count; no filtered ordered write stream,
  reusable fixture format, integrated native comparison or evidence receipt.

Thirteen shared-runner tests passed in the fresh generic suite. Ten additional
synthetic IN/OUT/string-I/O checks all rejected device access. Four target RNG
comparison negative controls also passed. These checks do not certify arbitrary
instructions, every supported CPU generation or every target fixture.

Unicorn emulates CPU operations and exposes instrumentation; it does not supply
the rest of a PC. This boundary is explicit in the
[official architecture description](https://www.unicorn-engine.org/docs/beyond_qemu.html).
The pinned [2.1.4 API](https://github.com/unicorn-engine/unicorn/blob/2.1.4/include/unicorn/unicorn.h)
provides instruction, memory and execution hooks. Instruction counts and host
timeouts are not recovered DOS CPU cycles, PIT/PIC scheduling or audio timing.

Some custom raster probes interpret selected VGA map-mask writes. Their own
reports correctly limit them to controlled indexed effects and source work.
That interpretation belongs in a qualified target/device adapter, separately
from the default device-free runner. Flat RAM equality cannot certify VGA
latches, scanout, interrupt ancestry or analog sound.

## Remaining friction

1. **Evidence and runner duplication.** The current integration uses separate
   scripts for launching/logging/timing, source bindings, frozen packets, host
   qualification and status updates. For example, `run_local.py` overlaps generic
   capture evidence but does not provide the same error/finalization contract.
   Audio calibration imports common comparison helpers from the target RNG
   verifier. These are concrete extraction candidates.
2. **Ordered effects need custom emulators.** The shared CPU runner cannot see
   overwritten writes or prove order from final RAM. Several target tools create
   another `Uc`, register hooks and implement their own stop/bound checks.
   Share the instrumentation, while keeping VGA interpretation target-local.
3. **Broad cache invalidation.** Stellar 7 acceptance puts every `tools/*.py` hash
   and the complete executable identity into every scenario key. One tool edit
   can invalidate unrelated cases. All 28 cases missed the latest cohort cache.
   A full executable change may legitimately invalidate all dependent cases;
   this audit does not claim those 28 misses were avoidable.
4. **Stale dependencies are found late.** Two current fidelity tests reject old
   controller-owner evidence. Rejection is correct, but a shared preflight could
   report affected records and prerequisites before a lengthy aggregate run.
   Never resolve this by merely refreshing hashes in a recorded pass.
5. **Status is still manually assembled.** Filesystem enumeration found 1,474
   immediate private analysis directories, 8,988 Python files recursively and
   230 freeze JSON files. These include copied/generated material, not 8,988
   unique experiments or a measure of waste. A small current index should be
   authoritative for retrieval; historical records should remain immutable.
6. **A demonstrated traversal inefficiency.** `audit_public_tree` sorts a full
   `rglob` before filtering ignored path components. A synthetic instrumented
   fixture confirmed descent into `.work/deep`, even though its files correctly
   produce no publication findings. Prune ignored directories before descent.
   No isolated wall-time speedup was measured for a proposed replacement.
7. **Environment setup leaks into verification.** Eight generic tests initially
   failed on sandbox-temp atomic renames. The same eight tests passed after
   selecting a workspace-local temp directory. A shared test/doctor invocation
   should make the temp root explicit and check required filesystem operations.
   The generic progress tests also hardcode `projects/Stellar7/.work` as their
   scratch root. Move that fixture to generic private test storage when making
   the temp-root change; reusable tests should not need a particular game tree.

The most recent natural route spent **57.102 s building, 1430.823 s replaying
and 6.027 s verifying**. Full acceptance took **486.169 s**; actual host execution
took **21.352 s**. Those are recorded milestone timings, not fresh audit reruns.
There were zero new original captures in that cohort. The long stage was native
replay, so a persistent DOSBox session would not accelerate that measured stage.
The current receipts do not separate native computation, instrumentation and
serialization; profile them before choosing an optimization.

There is insufficient comparable before/after data to claim an overall speedup
percentage or to attribute all development time to CPU emulation or any one
workflow choice.

## Prioritized reusable changes

These are proposed changes, not commands implemented by this audit. Extend the
existing harness and skill; avoid a second parallel workbench.

| Order | Deliverable | First migration and acceptance |
|---|---|---|
| 1 | Pruned publication traversal and explicit verification temp-root setup | Preserve all existing findings/order and symlink policy. Add a negative traversal test that fails if an ignored subtree is opened. Test create/rename/delete in the selected temp root without elevation. |
| 2 | Shared execution receipt and dependency preflight for native commands | Migrate one existing log/time wrapper. Record argv, cwd, declared environment, tool/source/binary identities, stage times, stdout/stderr, exit/error/timeout and terminal status. Preserve partial failure evidence; never automatically retry guest execution. |
| 3 | Optional filtered ordered RAM-write observations in `run_callback` | Default behavior/device rejection unchanged. Record sequence, CS:IP, address, width and written bytes. Cover repeated/overlapping/aliased writes, pre-write semantics, REP behavior and trace-cap overflow. Migrate one pure scratch-memory probe before a device adapter. |
| 4 | Versioned CPU experiment/fixture contract using that runner | Bind original/snapshot/relocations, expected entry bytes, registers, stack mode, overlays, stop/caps, comparison ranges and native invocation. Reset every independent case. Migrate the calibrated RNG case and a second TD3 case without changing compared fields or eligibility. No arbitrary embedded Python in plans. |
| 5 | Explicit evidence dependency graph, per-case cache inputs and generated current ledger | Detect stale/missing dependencies before execution, preserve recorded result separately from freshness. Unrelated declared code changes keep independent cases; used dependencies invalidate them. Incomplete declarations fail conservative qualification. New cache namespace; preserve old manifests. |
| 6 | Versioned program-index exporter on existing Ghidra queries | Functions/extents, calls, indirect unknowns, memory spaces/references and candidate aliases. Feed existing recovery accounting. Unknown extents stay unknown; indexing earns no behavioral credit. |

Persistent backend sessions and typed execution operations remain later work,
conditional on measured capture launch/restore/transfer costs. A default whole-PC
Unicorn emulation layer, automatic canonical-memory rewrite, per-game generic
renderer and another large workflow framework are not justified by this audit.

## Skill changes to make alongside implementation

Keep `reverse-reimplement-dos` as the existing entry point. Its linked references
are a better place for these details than several new overlapping skills:

- Select the deliverable and certification gates at the start; retain their
  separate results throughout. Do not silently lower an accepted fidelity goal.
- Name one retained boundary or missing dependency per experiment. Use original
  CPU execution for pure logic; use DOSBox for machine/device-dependent claims.
- Qualify a fixture once, reuse it while its relevant inputs remain identical,
  and batch meaningful branch/width/alias cases. Replaying a qualified reference
  is the normal fix loop; recapture when its boundary or provenance requires it.
- Integrate a complete operation/family and retained successor before expanding
  isolated probe coverage. Preserve unsupported rejection and a negative control.
- Preflight dependencies, run affected tests during a batch, and run the full
  aggregate at joined milestones. Report build/replay/compare costs separately.
- Generate the current ledger from receipts; append/link history instead of
  manually duplicating it across runners and reports.

One wording conflict should be resolved: the main skill's evidence-loop step 7
says to recapture after fixing, while the translation reference recommends
reusing qualified captures. Make reuse the explicit default without weakening
the conditions under which original evidence must be renewed.

## Fresh verification and reproduction

Private audit records are under `.work/audits/workflow-20261021/`:

- `inventory.json`: AST call-site counts, source hashes and scoped artifact counts.
- `generic-tests.log`: 296 tests in 102.455 s, initially 8 errors and 1 skip.
  All eight errors were sandbox-temp rename failures; 287 tests passed initially.
- `workspace-temp-recheck.log` and `.json`: the same eight tests pass unchanged
  in 0.904 s test time / 1.277 s process wall time with workspace-local temp.
  Across these runs, 295 tests passed and one hardlink-permission test skipped.
  This is not described as a single clean full-suite run.
- `rng-current-runner-calibration.json`: fresh current-runner exact CPU result;
  `rng-negative-controls.log`: four passing comparator controls.
- `ignored-tree-traversal.json`: demonstrated ignored-subtree enumeration.
- `unicorn-io-negatives.json`: all ten synthetic device accesses rejected.

Use the pinned optional dependency from `pyproject.toml`; no installation or
upgrade was performed. To reproduce generic tests in a suitable environment:

```powershell
$env:PYTHONPATH='src'
# Set TEMP/TMP to an existing writable workspace-local private directory.
python -B -m unittest discover -s tests -v
```

The private audit scripts refuse to overwrite their records. Use a fresh audit
directory for another run. Existing Stellar 7 milestone receipts and historical
test counts remain evidence of their recorded cohorts, not new audit results.
