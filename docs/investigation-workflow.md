# Reusable investigation workflow

These tools accept adapter-normalized evidence and portable experiment plans.
Application addresses, state meanings, resource formats and input routes belong
in private adapters. Public examples use generated data and relative paths.
Keep machine paths, executable locations and environment overrides in an
explicit private host profile under `.work`.

## Run a regression batch

Existing version 2 run plans support ordered batch execution.

```text
dos-re run-plan jobs.json --all-jobs --out-dir .work/batch --dry-run
dos-re run-plan jobs.json --all-jobs --out-dir .work/batch --host-profile .work/host.json
```

```json
{
  "format_version": 2,
  "jobs": {
    "positive": {
      "command": ["python", "-c", "print('synthetic pass')"],
      "expected_stdout": ["synthetic pass"]
    },
    "negative": {
      "command": ["python", "-c", "raise SystemExit(7)"],
      "expected_exit_code": 7
    }
  }
}
```

All jobs and declared input identities are preflighted before launch. Jobs run
in document order and stop on the first unmet expectation. Remaining jobs are
listed as skipped. Each job retains its original receipt and expectation result.
`batch-result.json` binds both files by hash. An expected nonzero exit keeps its
failed raw receipt. The batch result reports whether expectations were met.

Jobs may share existing `input_groups`. Bind executable files and runtime
libraries explicitly when their identities matter. Inputs are rechecked for
each job, including changes made by earlier jobs. Commands use argument arrays
and retain the existing host-profile expansion rules. Batch names must be
distinct portable directory names, including on case-insensitive filesystems.
Execution receipts and logs contain private paths and declared environment
values. Store them under `.work` and use the publication audit before sharing.

## Inspect the first divergence

```text
dos-re diff-trace .work/original.jsonl .work/native.jsonl --out-dir .work/difference --before 8 --after 4
```

The existing strict row comparison now optionally retains preceding and
following context. JSONL and gzip-compressed JSONL inputs are supported.
The output contains a comparison report and two indexed context files.
Missing fields, explicit nulls and missing rows remain distinguishable.
All fields participate in comparison. No timestamp fitting or row alignment
is applied. Context counts must be integers from zero through 1,024.

The comparison stops after the requested failure window. `complete` records
whether the source iterators were exhausted. `rows_examined` records the
compared prefix. A matching empty trace has zero rows and a null context window.
These are row-count bounds. Adapters should also bound each row's payload.
Input identities are checked before and after inspection.

Include progress counters, inputs, ownership and retained state in normalized
rows when investigating a stalled route. Inspect both sides around the earliest
difference before changing controls or downstream rendering. A shared stall
supplies evidence about the observed route and its starting conditions.

## Declare clocks and lifecycle boundaries

`diff-observations` validates complete event windows before comparing them.

```text
dos-re diff-observations .work/original/observations.json .work/native/observations.json --out-dir .work/event-difference
```

An observation manifest has the following shape. Replace the hash placeholder
with the actual lowercase SHA256 of the event file.

```json
{
  "format_version": 1,
  "events": {"path": "events.jsonl", "sha256": "<sha256>"},
  "clocks": {
    "simulation": {"rate_numerator": 40, "rate_denominator": 1},
    "audio": {"rate_numerator": 48000, "rate_denominator": 1},
    "instruction_boundary": null
  },
  "complete": true,
  "initial_owners": [],
  "final_owners": [],
  "end_clocks": {
    "simulation": {"epoch": 0, "tick": 1},
    "audio": {"epoch": 0, "tick": 1200},
    "instruction_boundary": {"epoch": 0, "tick": 100}
  },
  "provenance": {
    "execution": "controlled",
    "timing": "logical",
    "supplied": ["initial snapshot"]
  }
}
```

Each JSONL event has exactly `sequence`, `boundary`, `phase`, `owner`, `clocks`
and `state`. Sequence starts at zero. Boundary and owner are nonempty names.
Phase is `point`, `enter` or `leave`. State is an adapter-defined JSON object.
Every event supplies every declared clock using the same epoch/tick shape as
`end_clocks`. An enter pushes its owner. A leave must match the active owner.
Nested ownership and explicitly declared initial/final owner stacks are supported.

Use separate clocks for simulation updates, presentations, PIC time and audio
sample positions. A rate is a positive rational. A null rate identifies an
unscaled counter. Instruction-boundary counts have no implied elapsed time.
Ticks and epochs are unsigned 64-bit integers. Ticks are monotonic within each
epoch. A reset requires an explicit increment of one epoch. End clocks bound
the final visible or audible interval and must follow the last observation.

Clock definitions, initial/final owners, end clocks and all event rows compare
exactly. Use a common clock definition and origin in both adapters. Source
provenance is retained separately. Its execution and timing categories are
declarations requiring independent evidence. Default validation is bounded to
one million events. Missing, stale, truncated, overflowed or nonfinite evidence
is rejected. Transition snapshots should include the fields whose carry matters
across startup, menus, scene loads, cleanup and restart.

## Record passive backend observations

The pinned backend supports an opt-in bounded observer for fixed-cycle runs.
It runs on the emulation thread and adds no guest memory edits, execution stops
or explicit guest-cycle charges. Host execution overhead can increase.
Use an explicit supported CPU core and disable automatic cycle adjustment.

Supply `DOS_RE_HARNESS_OBSERVER_PLAN` and `DOS_RE_HARNESS_OBSERVER_OUTPUT` through
the private launch environment. Output must be fresh. The plan uses this text
format with adapter-resolved physical-linear instruction addresses.

```text
dos-re-observer-v1
start 0x10000
stop 0x10020
limit 1000
probe 0x10000 enter routine entry
probe 0x10020 leave routine return
event irq-dispatch
event interrupt-return-attempt
event dma-read-request
event dma-write-request
event display-complete
port 0x3c8
port 0x3c9
```

The addresses above illustrate a synthetic interval. Start and stop must be
distinct. Recording begins before the start instruction and finishes before
the stop instruction. At most 64 unique instruction probes and 64 unique ports
are permitted. Probe owner/boundary tokens contain at most 64 ASCII letters,
digits, underscores, dots or hyphens. Limits range from one to one million
events. Overflow is explicit and prevents complete import. A missing stop leaves
an incomplete log. Existing output files are rejected.

Device events record PIC interrupt dispatch, IRET attempts, DMA read/write
requests and completed renderer-source frames. Selected port writes record port,
value and width at the I/O entry point. IRET attempts can fault. DMA request sizes
can exceed transferred data. These event names describe their observation points.
Function entry/return probes can provide additional caller-qualified boundaries.

The observer records emulated PIC nanoseconds and an unscaled instruction-boundary
counter. Normal and full interpreter qualification uses the generated probe
below. Other cores, automatic cycle adjustment, full interrupt-service
duration inference and physical hardware timing require separate qualification.

```text
python scripts/qualify-observer.py --backend BACKEND_EXECUTABLE --out-dir .work/observer-qualification
dos-re import-observations .work/raw.jsonl --backend BACKEND_EXECUTABLE --observer-plan .work/observer.plan --execution controlled --supplied "initial snapshot" --out-dir .work/imported
```

The qualification script runs on Linux and requires NASM. It generates a DOS
program, compares observer-off/on registers, RAM and completed display content,
exercises device events and checks overflow. Renderer generation counters are
retained as diagnostics. Their equality remains unqualified.
Import binds the raw log, backend executable
and plan identities. Supply `--initial-owner` or `--final-owner` repeatedly for
windows that begin or end inside existing owners. Imports retain emulated timing
qualification. Existing captures retain their recorded backend identities.

## Summarize fidelity by evidence domain

Dependency graphs also accept version 2. Each evidence record adds `domains`,
`timing` and `supplied` to the existing version 1 fields.

- `domains` is a nonempty list of unique adapter-defined domains.
- `timing` is `unqualified`, `logical`, `emulated` or `physical`.
- `supplied` lists unique declared controls such as initial snapshots or loadouts.

Existing execution categories remain `component`, `controlled` and `natural`.
`evidence-status` reports outcome counts by execution, timing and domain.
Markdown output includes the added qualifications. Recorded failures and stale
passes retain their original outcomes. Freshness and fidelity are reported
separately. A current pass count supplies an inventory of declared passing
records. Broader coverage requires its own reviewed contracts.

See [the workbench](workbench.md) for command receipts and dependency contracts,
and [evidence boundaries](evidence-boundaries.md) for qualification requirements.
