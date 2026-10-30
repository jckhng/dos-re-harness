# Reusable capture plans

`capture-plan` validates a versioned request and uses the same adapter path as
`capture`. Store a plan when a capture would otherwise need a long command or a
new wrapper script. The plan does not change the backend's execution semantics.

```json
{
  "format_version": 1,
  "project": "../project.json",
  "scenario": "boot",
  "movie": "../movies/boot.movie.json",
  "adapter_arguments": {}
}
```

`project` and `scenario` are required. `movie`, `input_script` and
`adapter_arguments` are optional. Project/movie/input-script paths resolve
relative to the plan file. Adapter values remain opaque strings or finite
numbers, using the existing adapter's path and argument conventions. Only
argument names already declared by the adapter or scenario are accepted.
Unknown plan keys, unsupported versions and missing files fail before launch.

```text
dos-re capture-plan plans/boot.json --out-dir .work/captures/boot-01 --dry-run
dos-re capture-plan plans/boot.json --out-dir .work/captures/boot-01
```

The output directory is specified for each run; use a fresh or empty directory.
Dry-run prints the resolved argument array and does not create output files.
The existing `capture PROJECT SCENARIO ...` command remains supported.

## Evidence and failure handling

Both capture entry points freeze project, schema, scenario, movie, input-script,
backend-lock and Python harness source identities before execution. Existing
script files passed as adapter arguments are also hashed. This does not identify
every executable or transitive adapter dependency: retain backend/target-specific
binary manifests for strict qualification.

The final `harness_manifest.json` retains existing fields and adds:

- `input_observation`: `before_execution` for these CLI captures; legacy direct
  manifest-writing callers are labelled `manifest_creation` instead.
- `capture.mutable_baseline` and `capture.mutable_after`: before/after records
  for the configured specimen root. If an adapter uses a copied mount, its own
  manifest must identify that mount's initial and final contents.
- `execution.status`, `wall_seconds`, and a launch error when available. A
  completed adapter invocation does not by itself establish fidelity.
- For a plan, `contracts.capture_plan` binds the source file hash and
  `capture_plan` retains the resolved request.

Nonzero adapter exits, launch errors and keyboard interruption produce a final
manifest where possible. Hard process termination or filesystem failure can
still prevent finalization. Existing artifacts are not overwritten by capture.

## Complete state comparisons

`diff-state` now requires every schema field by default. `--strict` remains an
accepted explicit spelling. Use `--allow-missing` only for diagnostic partial
comparisons; skipped fields do not establish acceptance. Empty comparison schemas
are rejected. Memory parsing itself still supports partial dumps.

## Remaining migration

The remote driver now uses `RemoteConnections` for capture-scoped RSP/QMP
ownership. Connections open at the same boundaries; released QMP clients close
once, and remaining clients close when capture exits, including failed RSP setup
after a paused load. Cleanup attempts every client and preserves a primary
capture error. QMP memory fallback uses that capture's RSP reader, never another
capture's class-global reader. Direct legacy `QmpClient.set_memory_fallback`
callers remain supported outside this owned path.

This owns protocol connections only. It does not own the externally launched
backend process, reuse guest state, retry timed-out commands or introduce a
persistent backend session. Launcher/process ownership and typed execution
operations remain separate work. Synthetic loopback/fault tests cover the
migrated path. A live same-save-state comparison also passes on the locked backend;
see the improvement plan for the tested boundary and host build qualification.

Version 1 packages the existing scenario/movie/adapter interface. It does not
implement a new execution scheduler, persistent backend session, arbitrary
execution-operation graph, native comparison runner or content-addressed cache.
Those changes need independent integration tests; see
[the improvement plan](harness-improvement-plan.md).
