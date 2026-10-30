---
name: reverse-reimplement-dos
description: Evidence-first reverse engineering and faithful portable reimplementation of DOS software using specimen hashes, narrow Ghidra queries, DOSBox-X runtime capture, state-gated input movies, asset and audio recovery, and trace/frame differential testing. Use when analyzing DOS EXE or COM binaries, decoding game resources, recovering timing/RNG/presenter behavior, diagnosing fidelity mismatches, building deterministic validation harnesses, or publishing reproducible reverse-engineering checkpoints.
---

# Reverse and Reimplement DOS Software

Treat the original executable as the behavioral specification. Treat
decompiler output, names, structs, and inferred formats as hypotheses until
runtime evidence confirms them.

## Start With Boundaries

1. Establish whether the request targets the current repository, a named
   specimen, or a hypothetical workflow.
2. Inspect the repository, existing harness, dirty files, and target adapter
   only when the request identifies that target or asks for repository work.
3. Keep hypothetical and generic answers target-neutral. Do not import
   addresses, resource IDs, filenames, or conclusions from an unrelated
   workspace merely because it is available.
4. Hash the exact executable, data files, and baseline configuration.
5. Record version, provenance, emulator configuration, and mutable files.
6. Keep proprietary specimens, extracted assets, captures, memory dumps, save
   states, and Ghidra databases out of a public toolkit.
7. Keep the portable reimplementation independent of DOSBox, Ghidra, WSL, and
   the validation harness.

Do not mix evidence from different binary versions.

## Plan Translation and Integration

Read [references/translation-workflow.md](references/translation-workflow.md)
before substantial translation or when isolated matches stop advancing a retained
execution path. Map functions, dependencies and shared storage; write bounded
contracts and preserve aliases through canonical storage where appropriate.
Track mapped, specified, implemented, integrated and validated work separately.
Give each work package an owner, established interfaces and a continuous boundary
to advance. Do not require delegation or change an accepted fidelity goal.

## Build the Evidence Loop

Use Ghidra for static hypotheses, Unicorn for bounded CPU-level differential
experiments, and DOSBox-X for system-level validation. Compare reconstructed
C/C++ against the original at the tested contract and retained runtime levels.

Work in this order:

1. Create narrow static-analysis queries for functions, instructions, xrefs,
   strings, and scalar constants.
2. Define a stable state schema around observable anchors.
3. Capture the original with state- or screen-gated input, not startup sleeps.
4. Make the reimplementation emit the same state and input schema.
5. Compare traces at the first divergent tick.
6. Add a regression fixture before changing behavior.
7. Fix the earliest cause and replay qualified evidence. Recapture when the
   required boundary, inputs or provenance have changed.

Read [references/workflow.md](references/workflow.md) before designing a new
project or validation harness.

For repeated captures, prefer a versioned `dos-re capture-plan PLAN --out-dir OUT`
request over another wrapper script. Keep output fresh; use `--dry-run` to review
the resolved command. `diff-state` requires every field by default;
`--allow-missing` is a partial diagnostic, not an acceptance result. Read
[references/capture-recipes.md](references/capture-recipes.md) for batched
breakpoints, restored input tails, compact indexes and boundary precautions.

When a recovered subsystem has a narrow deterministic ABI, consider a
controlled hybrid substitution: replace that routine inside a private copy or
loaded image of the original, prove the replacement is invoked, and compare
the pristine and substituted runs from the same resumable boundary. Read
[references/hybrid-substitution.md](references/hybrid-substitution.md) before
using this method. Treat it as a contract-verification ladder, not as the
portable deliverable.

For a bounded, device-free real-mode callback, use the optional harness
`dos_re_harness.unicorn_probe.run_callback` runner for active differential
experiments. Keep fixture setup in the target adapter. Read
[references/unicorn-microprobe.md](references/unicorn-microprobe.md) before
using it.

1. State the competing instruction-level hypotheses and choose inputs that
   distinguish them. Exercise relevant branch, signedness, overflow and
   truncation boundaries rather than starting an unrestricted input sweep.
2. Preserve the required relocated code, callees, tables, globals, segments,
   registers and stack convention in a qualified private snapshot. Function
   bytes alone may be insufficient. Distinguish naturally observed inputs from
   synthetic controls and record any violated or unproven input invariants.
3. Execute the original code and reconstructed implementation from equivalent
   initial conditions, restoring the baseline for each independent case.
   Record inputs, compared fields, completion or trap boundaries, commands
   and hashes. Report unsupported or partial executions separately.
4. Compare final state and, where ordering matters, intermediate effects.
   Final memory equality cannot prove write order or reveal overwritten writes.
   The runner returns final memory/registers, selected register observations and
   optional bounded ordered RAM writes; trace mode rejects executed-code-page writes.
5. Qualify the probe against independent DOSBox-X evidence as described in the
   reference. Preserve a reproducing regression before one narrow fix, then
   rerun the affected retained original/native path after integration without
   importing later oracle state or repairing native outputs.

A passing micro-probe establishes only the tested controlled-call contract.
Finite sweeps do not prove all executions. Unicorn instruction counts do not
establish elapsed cycles, PIT/PIC scheduling or IRQ delivery. Device-dependent
behavior and continuous timing require system-level evidence.

Use `run-plan` for native command receipts, `probe-plan` for versioned CPU fixtures,
and `evidence-status` for declared dependency freshness and a current ledger.
Read [the workbench contracts](../../docs/workbench.md) before migrating an
experiment. Preserve its compared fields, original oracle and eligibility; a
cache hit or successful process exit does not qualify fidelity.

When an MZ import exposes only a packer or relocation stub, use the harness
`unpack-mz` command with a pinned `mzexplode` binary. Hash the tool, packed
input, unpacked output, and command in a private manifest. Import the unpacked
copy for static analysis, but continue to capture and validate the pristine
packed executable.

## Recover Behavior, Not an Approximation

- Preserve integer width, overflow, signedness, fixed-point scale, truncation,
  update order, entity iteration order, RNG call order, and timer granularity.
- Map every recovered event through:
  `call site -> resource ID -> source bytes -> decoder -> draw/play arguments
  -> timing/lifetime -> hardware remap`.
- Prefer recovered original resources over procedural replacements whenever a
  resource exists.
- Separate asset decoding from presentation logic.
- Separate audio resource identity, codec, device remap, call timing, loop
  lifetime, and mixer behavior.
- For Sound Blaster/OPL work, use the generic launcher’s optional
  `-OplLogPath` and `-OplTickLinear` parameters. The pinned DOSBox-X backend
  logger records `tick_ms,reg_hex,value_hex`; when `-OplTickLinear` names a
  guest word containing the loop tick, it records
  `tick_ms,loop_tick,reg_hex,value_hex` without adding a breakpoint or changing
  guest execution. Keep the raw CSV under `.work`, compare register/value
  order before waveform data, and record when the backend exposes only PIC
  timestamps so that an apparent audio mismatch is not mislabelled as a
  simulation mismatch.
- When a verified blocking guest call exceeds the generic launcher's
  10-second RSP/QMP deadline under instrumentation, raise `-RemoteTimeout`
  for that capture only. Do not substitute a longer host wait for an exact
  guest-state or safe-instruction boundary.
- Run `dos-re inspect-wave` on captured and portable PCM before opening or
  embedding full sample data. Use `dos-re diff-wave` only with explicit
  mixdown, tolerance, or frame-skip transforms, and retain those transforms
  in the comparison report.
- Recover shared presenters once. Reuse them for every original path that calls
  them rather than creating visually similar scene-specific replacements.

## Validate Temporal Presentation

A terminal screenshot is insufficient for animation, cutscene, UI, or audio
fidelity. Capture ordered frames and state at meaningful ticks.

Check:

- frame cadence and hold durations;
- sprite origin and fixed-point coordinate conversion;
- draw order before, during, and after occlusion;
- object removal timing;
- page flipping, dirty rectangles, and intentional page residue;
- palette state and indexed pixels separately;
- overlay clearing before the next banner or scene;
- skip/interrupt behavior and its exact terminal state;
- sound start, stop, remap, repetition, and actor lifetime.

Read [references/failure-modes.md](references/failure-modes.md) when a scene
looks close but remains visibly or audibly wrong.

For a complete route, consolidate the evidence at one logical tick boundary.
The target capture must provide exact post-display screenshots and decoded
state checkpoints; the portable side must provide an indexed frame sequence,
semantic JSON series, and (when available) OPL/audio event traces.  A useful
target-local pattern is:

```text
verify_<route>_golden_route.py
make_<route>_logical_tick_video.py
```

The verifier should report first divergence by domain (frame/DAC, semantic
state, audio/OPL), changed regions and palette frontier, and draw-owner
candidates.  It must keep unresolved palette or timestamp alignment as an
evidence frontier rather than treating it as an exact match.  The video
renderer should key every frame to the logical tick, label the source clock,
and emit a manifest with input hashes and encoded frame count; native capture
timing is not a substitute for tick alignment.

## Use Controlled Warps

Use runtime state waits first. When a late scene is expensive or unreliable to
reach, use a documented test-only warp, snapshot, register restore, or private
patched specimen.

Always record:

- pristine specimen hash;
- patch or memory poke;
- restored registers and memory;
- entry state and expected invariant;
- capture command and backend lock;
- whether the warp bypasses initialization relevant to the scene.

Never mistake a convenient warp for proof that natural scheduling matches.

## Keep Analysis Searchable

Maintain machine-readable symbol and state maps. For every semantic rename,
record address, proposed signature, evidence, confidence, and superseded
hypotheses.

Query small function bundles instead of storing giant decompiler dumps. Include
decompile text, disassembly, xrefs, callers, callees, constants, and relevant
runtime observations.

## Enforce Phase Gates

Do not modernize during compatibility work. Delay controller redesign,
widescreen changes, float conversions, ECS rewrites, bug fixes, and renderer
cleanup until the original path is stable.

Use explicit modes when modernization begins:

- faithful compatibility path;
- optional bug-fix path;
- modern controls or presentation path.

Read [references/evidence-and-release.md](references/evidence-and-release.md)
before creating public checkpoints or shipping a harness.

## Diagnose Before Editing

For each mismatch:

1. State the earliest observed divergence.
2. Classify it as state, timing, resource, coordinate, draw-order, palette,
   audio-routing, or harness error.
3. Identify the smallest original-binary experiment that distinguishes the
   competing hypotheses.
4. Capture the experiment.
5. Update the evidence map.
6. Implement one narrow fix.
7. Run state, temporal frame, and audio validation as applicable.

Do not tune downstream pixels while upstream state still diverges.

During an integration stall, tie each probe campaign to a demonstrated
continuous divergence or a required shared contract. State which boundary
advanced or which specific prerequisite was established; additional isolated
matches alone do not close the retained execution or acceptance gate.

## Preserve Agent Discipline

- Keep target adapters outside the reusable harness core.
- Keep tasks narrow: do not combine decompiler renaming, asset decoding,
  renderer refactoring, and gameplay rewrites in one change.
- Do not revert mutable specimens or unrelated user changes.
- Record uncertainty instead of inventing behavior.
- Prefer reproducible commands, manifests, hashes, and regression tests over
  narrative claims.
- Keep unpacked executable images and their analysis databases under `.work`;
  never substitute an unpacked derivative for pristine runtime evidence.
- Stop and inspect the harness when repeated manual comparison produces
  contradictory conclusions.
