# Capture recipes and boundary checks

Read when configuring repeated breakpoints, restored input tails or checkpoint
comparisons. Keep target addresses and decoding in the target adapter.

When locating a frontier across nearby logical ticks, capture an ordered state
checkpoint series in one emulator run. Keep every checkpoint independently
comparable, hash nested artifacts in the parent evidence manifest, and report
only observed exact/divergent ticks. Do not treat a known divergence as a
passing regression merely because it is expected.

Before launching repeated Nth-hit probes at one post-resume breakpoint, batch
the required hit ordinals into one capture. Use the harness
`--post-resume-break-hit-series` adapter capability and decode the resulting
`checkpoints/breakpoint_hit-*` artifacts with a target-local analyzer. Do not
repeat full emulator startup solely to change the requested hit count.

When a paired-boundary capture uses a preparatory state series only to absorb
save-state drift, set `--checkpoint-post-display-scope post-resume-next` if
only the final paired boundary needs exact running-screen evidence. This
retains the preparatory state checkpoints while avoiding a display stop,
self-loop, DAC dump, and screenshot for each candidate value.

Inspect `capture.stop_boundary` in every `plan-state-tail` report. If
`requires_explicit_input_phase` is true, the requested terminal value shares
one or more input transitions. Select a transition-free boundary when the
question permits it; otherwise prove whether the capture is before input,
after input is queued, or after input is consumed. Do not compare such a stop
as an unqualified logical-tick state.

For a restored late-state capture, prefer `plan-state-tail` with
`--sliced-input-out` and `--sliced-input-manifest`. Use the generated capture
arguments unchanged. This reconstructs held keys, binds only the validated
post-resume input stream, and prevents accidental replay of pre-resume events.

When a restored state needs no further input transitions, omit the input
script and configure only the state-input hook, state address, width, and stop
value. Prefer an immediate halted save at that stop so checkpoint creation
does not execute an extra guest instruction.

For the same problem in an ordinary startup movie, use the generic
`breakseries:<segment>:<offset>:2+9+17` action. Reserve commas for separating
movie actions. Use portable-only tests for routine iterations, turbo captures
only for a target domain proven by a short A/B capture, and pinned non-turbo
proof captures for any domain where turbo diverges.

When a subsystem breakpoint must be correlated with a running state series,
use the generic concurrent side-breakpoint controls. Arm it at a state value
that excludes startup noise and cap the number of side hits when the routine
is high frequency:

```text
--adapter-argument resume_side_break_segmented=0x1234:0x5678
--adapter-argument resume_side_break_start_value=1
--adapter-argument resume_side_break_max_hits=128
```

The capture writes `side_breakpoint_trace.json` with registers and the
correlated state field. Treat a capped trace as a prefix boundary; report the
cap and do not claim full-route hardware parity from it.

When the breakpoint ABI exposes an address/value register pair, first run the
generic `dos-re extract-write-trace` command to produce an ordered, masked
stream and hash. Add device- or target-specific grouping, tick correlation,
and semantic names in a target-local analyzer.

Read `capture_summary.json` or run `dos-re summarize-capture CAPTURE` before
opening full register metadata. Load `remote_runtime_registers.json` only when
the compact counts, hashes, final registers, and checkpoint index are
insufficient.

Use `dos-re index-checkpoints CAPTURE --artifact FILE` when a repeated
breakpoint analysis needs ordered whole-file hashes, a fixed artifact slice,
or selected registers at every `breakpoint_hit-N`. Keep segment arithmetic,
field names, and subsystem meaning in the target-local analyzer.
