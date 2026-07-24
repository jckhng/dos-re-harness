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

## Build the Evidence Loop

Work in this order:

1. Create narrow static-analysis queries for functions, instructions, xrefs,
   strings, and scalar constants.
2. Define a stable state schema around observable anchors.
3. Capture the original with state- or screen-gated input, not startup sleeps.
4. Make the reimplementation emit the same state and input schema.
5. Compare traces at the first divergent tick.
6. Add a regression fixture before changing behavior.
7. Fix the earliest cause, then recapture and repeat.

Read [references/workflow.md](references/workflow.md) before designing a new
project or validation harness.

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

## Preserve Agent Discipline

- Keep target adapters outside the reusable harness core.
- Keep tasks narrow: do not combine decompiler renaming, asset decoding,
  renderer refactoring, and gameplay rewrites in one change.
- Do not revert mutable specimens or unrelated user changes.
- Record uncertainty instead of inventing behavior.
- Prefer reproducible commands, manifests, hashes, and regression tests over
  narrative claims.
- Stop and inspect the harness when repeated manual comparison produces
  contradictory conclusions.
