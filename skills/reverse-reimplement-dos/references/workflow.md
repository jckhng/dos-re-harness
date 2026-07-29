# Evidence-First DOS Reimplementation Workflow

## Contents

1. Specimen and rights boundary
2. Static analysis
3. Resource recovery
4. Runtime capture
5. Compatibility core
6. Differential validation
7. Scripted presentation
8. Audio
9. Portability
10. Completion gates

## 1. Specimen and Rights Boundary

Create a specimen manifest before analysis:

- SHA-256 of every executable and data file;
- release/version provenance;
- emulator CPU, cycles, video, sound, and input configuration;
- mutable files such as configuration, high scores, and saves;
- known differences from other releases.

Run captures from a clean mount. Overlay known baseline mutable files rather
than letting the original alter the specimen directory. Hash the overlay source
and include it in the evidence manifest.

Do not distribute proprietary source material through fixtures. Public
fixtures should contain schemas, hashes, generated numeric reports, and
freely-licensed examples.

## 2. Static Analysis

Expose narrow Ghidra headless operations:

- list programs and functions;
- decompile one function;
- dump instructions for one range;
- find xrefs and callers;
- find scalar/resource-ID use;
- export a structured function bundle.

Maintain semantic maps with:

```json
{
  "address": "1234:5678",
  "name": "candidate_name",
  "signature": "void candidate_name(uint16_t id)",
  "confidence": "medium",
  "evidence": [
    "caller passes resource index",
    "runtime capture writes indexed pixels"
  ]
}
```

Do not rename from appearance alone. Confirm decompiler types against
instructions, calling convention, segment use, and runtime state.

### Packed MZ executables

If the original MZ import exposes only a loader stub, unpack a private
derivative with the harness:

```powershell
pwsh -NoProfile -File scripts/dos-re.ps1 unpack-mz `
  projects/target/.work/specimen/release/GAME.EXE `
  projects/target/.work/unpacked/GAME.UNPACKED.EXE `
  --tool /absolute/path/to/mzexplode `
  --wsl-distribution Ubuntu
```

The command writes an adjacent JSON manifest containing the mzexplode binary,
packed input, and unpacked output hashes. Use the unpacked image to recover
code and relocations in Ghidra. Keep the packed executable as the runtime
behavioral specification and record both hashes in analysis notes. Never
publish the unpacked derivative.

## 3. Resource Recovery

Inventory every resource record before classifying it. Do not assume a
zero-size visual header means an empty resource; it may identify audio, code,
metadata, or a special decoder path.

For each format:

1. preserve source offsets and hashes;
2. decode to a stable raw representation;
3. test known dimensions, counts, and hashes;
4. render diagnostic output separately from runtime integration;
5. map consumers through xrefs and runtime calls.

Compiled sprites may contain blitter instructions rather than ordinary bitmap
rows. Recover their execution semantics or translate them into an equivalent
indexed representation without changing origin, clipping, transparency, or
palette behavior.

Use a fidelity map:

```text
event -> call site -> resource ID -> decoder -> coordinates -> timing -> status
```

Statuses should distinguish recovered, call-path-confirmed, integrated,
validated, and placeholder.

## 4. Runtime Capture

Start with stable anchors:

- frame or simulation tick;
- current level/room/state;
- RNG state;
- entity count and selected entity fields;
- player/camera coordinates;
- score/health/ammo;
- transition flags;
- framebuffer and palette hashes.

Prefer state-gated actions:

```text
wait for title signature
press key
wait for menu signature
press key
wait for frame_tick >= N
capture
```

Wall-clock sleeps are a fallback, not deterministic replay. Move repeated
sequences into versioned input movies. For strict parity, tie input changes to
emulated ticks or explicit state transitions.

Capture registers and segment bases with memory. In real mode, record whether
addresses are segment-relative or linear. Do not compare a DS-relative field
against an absolute rewrite address.

When several nearby state values must be compared, stop on one stable
breakpoint and capture the requested values in order during the same emulator
run. Each checkpoint must contain enough memory and register evidence to be
compared independently. Hash nested checkpoint files recursively, use named
workspaces for alternate boundaries, and keep confirmed-identical regressions
separate from known-divergent frontier observations.

For several call ordinals at the same post-resume breakpoint, pass one
strictly increasing series through the target adapter:

```text
--adapter-argument post_resume_break_segmented=0x1234:0x5678
--adapter-argument post_resume_break_hit_series=2,9,17,31
```

The capture writes `checkpoints/breakpoint_hit-2` and the other requested hits
without rebooting DOSBox-X. Keep breakpoint-specific decoding target-local;
the generic harness records registers and requested memory artifacts.

Inspect captures through the compact index first:

```text
dos-re summarize-capture projects/target/.work/captures/probe
```

Use `--json` for the compact structured form or `--out PATH` to materialize
it. The summary hashes large embedded input scripts and state records instead
of expanding them. The full evidence remains authoritative on disk.

## 5. Compatibility Core

Implement a headless deterministic core before polishing presentation:

- fixed-step update;
- explicit integer-width compatibility helpers;
- original RNG and seed behavior;
- replayable input;
- original entity/update ordering;
- state trace output matching the original schema.

Keep rendering and audio consumers outside the simulation where the original
contract permits it. Do not let host frame rate alter simulation order.

## 6. Differential Validation

Compare in this order:

1. input transition;
2. branch/state flags;
3. RNG state and consumption;
4. entity creation/removal and ordering;
5. coordinates and counters;
6. palette and indexed framebuffer;
7. audio events and rendered waveform.

Report the first divergent row and fields. A late visual mismatch often starts
as an earlier state, RNG, or scheduling mismatch.

When a mismatch is intermittent, capture hidden scheduling fields and the full
RNG path before adjusting timing constants.

## 7. Scripted Presentation

Recover presenter control flow rather than transcribing what one playback
looks like.

Identify:

- entry state and callback;
- per-tick update routine;
- actor selection source;
- movement target and sprite frame progression;
- resource IDs and draw coordinates;
- layer changes around occluders;
- door/overlay state lifetime;
- sound calls and delays;
- shared terminal presenter;
- skip/interrupt branch;
- final screen and cleanup.

Capture temporal sequences around state transitions. Draw order can change at
an occlusion threshold: an actor may be above a structure while approaching
and below its foreground layer after entering.

Treat old page contents as state. DOS double buffering, partial clears, and
dirty rectangles can make page residue part of the original output.

If multiple paths end in the same destruction or surrender scene, prove
whether they call a shared presenter and implement that presenter once.

## 8. Audio

Validate six separate layers:

1. resource bytes;
2. codec/command decoding;
3. device-specific ID remap;
4. call site and arguments;
5. start/stop/loop lifetime;
6. mixer and emulator configuration.

A recognizable but wrong sound usually indicates incorrect resource routing,
codec interpretation, or device remapping rather than a mixing problem.

Persistent actor audio must follow actor lifetime. Do not reduce an engine,
alarm, or ambience sound to a scene-entry one-shot.

When IDs remain ambiguous, export isolated WAV candidates with hashes and ask a
human to label them. Record that identification as evidence rather than
repeatedly guessing by ear.

## 9. Portability

Keep three layers:

- host-neutral schemas, movies, comparisons, and evidence;
- replaceable original-binary capture backend;
- independently portable reimplementation.

Use portable C/C++, SDL, and CMake for the product. Isolate OS integration.
Load user-provided original data at runtime when redistribution is not allowed.
Do not require WSL, DOSBox, Ghidra, or the harness to run the reimplementation.

## 10. Completion Gates

Use explicit gates:

- Build: clean Windows and Linux builds and unit tests.
- State: deterministic headless state traces match selected scenarios.
- Runtime: natural original scheduling and rewrite traces agree.
- Presentation: temporal indexed-frame/palette comparisons pass.
- Audio: event routing, lifetime, and waveform comparisons pass.
- Release: public-tree audit, mixed-license audit, reproduction commands, and
  evidence manifests pass.

Do not call a project faithful solely because it is playable or terminal
screens look similar.
