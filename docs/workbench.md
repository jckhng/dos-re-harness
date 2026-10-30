# Reusable experiment workbench

These commands extend existing capture/comparison tools without changing target
acceptance. Keep original files, RAM, plans with private paths and outputs under
ignored `.work`. Process success, current file identities and fidelity are separate.

## Tests and publication audit

```powershell
./scripts/run-tests.ps1
./scripts/run-tests.ps1 -TempRoot .work/test-temp -Pattern test_unicorn_writes.py
```

The shared `python -B scripts/run_tests.py` runner checks create/rename/delete
and scopes TEMP/TMP/TMPDIR/PYTHONPATH to the test child. `-Python` selects an interpreter;
`-DependencyPath` adds an existing dependency directory without installing it.
Use the pinned optional `unicorn` extra for CPU tests. Generic progress tests use
`.work/tests`, independently of targets. Publication auditing prunes ignored
directories before enumeration, preserving finding order and symlink policy.
For publication use `audit-public-tree --staged` (exact index bytes) or
`--paths-from .work/public-files.txt` (explicit new-file selection).
See [configuration and publication](configuration-and-publication.md) for the
private host-profile contract, publication boundaries and data-free CI.

## Native command receipts

For repeated experiments, run-plan v2 adds named jobs, selected input groups,
explicit host tool prefixes/variables, environment removal and expected failures.
Use `run-plan jobs.json --job NAME --host-profile .work/host.json --out-dir OUT`.
The optional profile is never auto-discovered. Expected failures retain raw failed
receipts; `job-result.json` reports expectations separately. See the
[v2 contract and examples](configuration-and-publication.md#portable-jobs-and-private-profiles).

Run-plan v1:

```json
{
  "format_version": 1,
  "command": ["python", "-B", "verify.py"],
  "cwd": ".",
  "environment": {"PYTHONPATH": "../../src"},
  "timeout_seconds": 120,
  "dependencies_complete": false,
  "inputs": [{"path":"verify.py","sha256":"<sha256>"}]
}
```

```text
dos-re run-plan experiment.json --out-dir .work/run-01 --dry-run
dos-re run-plan experiment.json --out-dir .work/run-01
```

Plan file paths resolve against the plan; command arguments/environment values
retain tool semantics. `cwd` defaults to the plan directory. Commands are argument
arrays without shell expansion; input is closed. Use a file argument for input
scripts. Output must be fresh. The library API is `execution.run_command`.

`stdout.log`, `stderr.log` and `receipt.json` retain requested/executed argv,
resolved tool hash, cwd, declared environment overrides, before/after identities,
exit/error/timeout and preflight/execution/total wall time. Statuses: `success`,
`failed`, `preflight_failed`, `timeout`, `launch_error`, `interrupted`. Stale or
missing inputs prevent execution; partial failure output survives. No retry is
automatic. The timeout covers the immediate command, not a process-tree supervisor.

`inputs_unchanged` is separate from exit status. CLI exit 0 requires success and
unchanged inputs; failed execution/preflight returns 1, invalid configuration 2.
Dry-run writes nothing. Dependency completeness is a caller declaration; imports,
DLLs and hidden environment state are not discovered automatically. Receipts
establish execution only, never behavioral qualification.

## CPU experiment plans

Probe-plan v1 runs one bounded 16-bit call from complete RAM/register snapshots:

| Required field | Meaning |
|---|---|
| `format_version`, `id`, `scope` | Integer 1; nonempty identity and tested domain |
| `files` | Exactly `specimen`, `memory`, `registers`, `expected_memory`, `expected_registers`, `calibration`; each a `{path,sha256}` binding |
| `entry`, `stop` | `[segment,offset]`, integer words |
| `entry_bytes` | Nonempty expected original entry bytes as hex |
| `return_kind` | `near`, `far` or stack-preserving `snapshot` |
| `max_instructions` | Positive integer cap |
| `register_overrides` | Explicit fixture registers; no entry CS:IP change or ambiguous low/extended aliases |
| `overlays` | Explicit `{address,bytes}` mutations, or `[]` |
| `compare` | `{memory_ranges:[[start,end],...],registers:[name,...]}`, nonempty selections |

Optional positive integers `timeout_us`, `stop_hit_count`, `max_writes` default to
5000000, 1, 4096. Optional `write_ranges` selects half-open linear RAM intervals.
Near/far mode pushes a synthetic return: if a snapshot already contains that
return, declare the caller-SP override. Snapshot mode preserves the existing
stack, including captured interrupt frames, without inventing device/IRQ state.
Register files can wrap the mapping in `registers`. DOSBox linear EIP is normalized
to relative IP; comparisons are explicitly 16-bit. Expected RAM must be equal length.

```text
dos-re probe-plan private-probe.json --out-dir .work/probe-01 --dry-run
dos-re probe-plan private-probe.json --out-dir .work/probe-01 --cache-dir .work/probe-cache
```

Each uncached run creates a fresh CPU/fixture. Outputs are `ram.bin` and
`report.json`; unsupported CPU execution retains a `rejected` report. Reports
include first memory/register differences, comparison selections, mutations,
ordered writes, identities and wall time. Classification is always
`controlled_imported_snapshot_non_promotable`. Calibration bindings declare
provenance; their contents/transitive ancestry are not automatically qualified.
Keep independent DOSBox calibration and eligibility in the target adapter.

Optional `native` is an object containing `plan` and `expected_json` file bindings.
The run-plan executes via the receipt layer; stdout must structurally equal the
expected JSON. The adapter owns its reference/schema. Expected JSON is read before
execution, so rewriting it cannot manufacture a pass. Native comparisons are
uncached. Related CPU contracts can share baseline files but reset independently.

CPU-only caching uses a separate `dos-re-probe-v1` identity covering the plan,
declared files, CPU runner/support sources, interpreter/binding and Unicorn native
libraries. Unrelated target tools are excluded. Hits validate report/RAM hashes;
corruption rejects without overwriting evidence. Input mutation prevents cache
writes. Historical target acceptance caches and criteria remain unchanged.

## Ordered RAM effects

`run_callback(..., write_ranges=((start,end),...), max_writes=N)` adds
`result.writes`: sequence, instruction-hook ordinal, CS:IP, address, pre-write
bytes and written bytes; width is their length. Intersecting accesses are recorded
whole once, even across multiple filters. Repeated/overlapping effects are not
merged. Fixture/synthetic-return writes are excluded. Overflow rejects rather
than returning truncated success.

Tracing is off by default and retains interrupt/I/O/unmapped-memory rejection.
Trace mode rejects writes to executed code pages because Unicorn can retry
translation and repeat pre-write hooks there. Hook ordinals/REP observations are
not DOS cycles. VGA/OPL interpretation remains target/device-specific.

## Dependency preflight and current ledger

```json
{
  "format_version": 1,
  "artifacts": [{"id":"source","path":"verify.py","sha256":"<sha256>"}],
  "records": [{"id":"component-case","dependencies":["source"],
    "dependencies_complete":true,"stage":"integrated","execution":"controlled",
    "recorded_result":"pass","scope":"Bounded contract, owner and next boundary"}]
}
```

```text
dos-re evidence-status dependencies.json
dos-re evidence-status dependencies.json --format markdown --out .work/current.md
```

Dependencies name files or records. Unknown IDs, duplicate IDs and cycles reject.
Missing/stale dependencies propagate. Complete records require nonempty inputs.
Freshness (`current`, `stale`, `missing`, `incomplete`) never rewrites recorded
outcomes (`pass`, `fail`, `not_run`, `unsupported`). Stages are declared `mapped`,
`specified`, `implemented`, `integrated`, `validated`; execution is `component`,
`controlled`, `natural`. Use separate records for claims with different evidence.

Exit 1 means a noncurrent record; a current recorded failure remains visible.
Outputs must be new. Scoped cache keys exclude unrelated records, but do not
prove passing behavior or automatically complete dependency declarations. Never
repin an old pass: requalify the changed contract and add a new record. Existing
`progress` still handles reviewed extents and natural-playability accounting.

## Static program index

`scripts/ghidra-query.ps1 -Query program-index ... -ReadOnly -NoAnalysis
-Args FRESH_INDEX_JSON` exports existing functions/body ranges, calls including
unresolved calls, memory/stack references, address spaces, imported-file SHA256,
confidence and limits. It creates no analysis or verified extents. Empty aliases
means unanalysed, not no aliases. Ghidra project ownership rules still apply.

```text
dos-re program-index private-index.json --image IMPORTED_IMAGE --inventory-out .work/mapped.json
python -m dos_re_harness.progress .work/mapped.json --out .work/progress.json
```

The image hash must match the export. Import seeds mapped functions only: unknown
file extents, zero reconstruction credit, no integrated/validated claims and an
incomplete inventory. Review runtime/file mapping and pristine-specimen lineage
before adding extents or recovery credit.
