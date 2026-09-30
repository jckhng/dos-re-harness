# Evidence Boundaries And Recovery Lessons

These lessons apply across DOS targets. Addresses, resource IDs, device setup
ABIs, sprite tables and scene-specific conclusions belong in target adapters.

## Budget Evidence Before Capture

Write down the behavior, boundary and acceptance question before recording.
Use source analysis and short original probes to select fields and phases;
do not sample whole memory and every video page across a long route by default.
Set wall-time, event and compressed-byte caps, and stop after the first useful
divergence rather than replaying its cascades.

Pin and reuse an audited original route across native revisions. For routine
regression, compare ordered state fields and exact page/palette hashes in a
stream; retain full memory/pages at checkpoints and around failures. Validate
any compact representation against a full capture before replacing that
capture as evidence. Hash equality proves only the observed content, not
unrecorded branches, visible hold duration or audio timing. Keep a separate
bounded release gate and an explicitly labeled exhaustive research backlog;
do not silently weaken a frozen criterion to fit a cheaper capture.

## Distinguish The Clocks

A simulation tick, hardware timer tick, completed page flip, audio interrupt
and device sample are different observations. A presenter may freeze simulation
while displaying multiple pictures. An interrupt may service music and effects
through different divisors, while a device drains its own FIFO independently.

Record the actual clock and phase at each boundary. Compare ordered content,
visible holds, entry latency, input polling and audio lifetime separately.
Matching every selected image is not proof of cadence or of uncaptured frames.
Use [the presentation contract](presentation-contract.md) for normalized holds
and PCM sample accounting. Do not copy observed emulator execution cost into
the portable game's authored delay constants.

## RAM Restoration Is Not Device Restoration

A saved RAM/register image may restore a driver's cached timer rate without
restoring the PIT, DMA, FIFO, audio callback, or interrupt-service state. A
subsequent setup routine may incorrectly skip hardware programming because
the cache says initialization already happened.

For each capture record:

- natural startup, full emulator save state, RAM-only restore, or controlled call;
- restored memory/register ranges and instruction-byte checks;
- backend build/configuration, original device detection result and setup calls;
- which hardware state is actually restored or independently reinitialized;
- remaining timing/provenance limitations and any overrides.

Use a fresh isolated host when device transitions cannot be reproduced safely.
Executing original initialization is stronger than writing a presence flag,
but is still not equivalent to natural menu selection or complete hardware
restoration. A backend flag alone is not evidence of physical timing parity.

## Prepared Is Not Submitted

For buffered audio, trace these stages independently:

`resource -> decode -> prepare -> submit -> consume -> completion -> owner release`

A padded block can be read and mixed but discarded before submission. The
first queued block can contain silence or retained data rather than payload.
Another voice can keep the queue alive after the first voice completes. A
repeating voice can have different tail behavior from an isolated one-shot.

Trace buffer selectors, cursor/count pairs, voice lifetimes and callback order.
Compare submitted bytes first, then nominal PCM, then emulator/hardware timing
and waveform. Do not infer byte rate from interrupt frequency, truncate every
resource based on one one-shot capture, or apply a per-voice delay to a shared
queue. Extend coverage across idle start, overlap, late admission, replacement,
repeat, reset, explicit stop and backend changes before claiming closure.

## Prove The Test Detects The Old Error

Keep a negative control: the previous incorrect runtime or a synthetic corrupted
trace must fail the new oracle. Include adversarial cases for omitted/reordered
events, missing final holds, wrong clock rates, invalid counter widths, boolean
values masquerading as numeric configuration, and relabelled backends.

Do not silently turn known differences into passes. A masked/aligned comparison
can help diagnosis only when its transform is explicit; it cannot replace the
strict acceptance result. A waveform correlation or nominal-byte match does
not certify device clock phase, analog filtering or whole-scene audio parity.

## Recover Shared Ownership Boundaries

Scene cleanup, mixer reset, actor release and music teardown may be separate
operations. Test each alone and in combinations. Held pictures should advance
PCM without reapplying events. Input received before a flag/key polling boundary
may be ignored, latched or consumed later; held and released keys need separate
tests. Compare retained pages independently from the now-cleared actor table.

## Query Without Destroying Evidence

Use explicit read-only Ghidra queries and keep the project hash baseline.
Skipping auto-analysis alone does not prevent saved edits. Read raw instructions
when segmented aliases, indirect callbacks or switch arms contradict the
decompiler. A matching scalar displacement is only a candidate until segment
state and addressing mode establish its effective address. See the
[Ghidra cookbook](ghidra-query-cookbook.md).

## Delegate With Integration Gates

Give agents disjoint file scopes and bounded questions. Reserve emulator/device
sessions, shared Ghidra projects, builds and final integration for one owner.
Do not compile while another worker edits shared headers. Require evidence paths
and whether tests actually ran; review agent conclusions against original code.
An odd behavior in the portable runtime is not automatically a fidelity bug if
the original has the same queue/update ordering.

Build dependent targets sequentially when they share generated resources.
Record binary hashes after the final build, not before it. Use isolated test
directories so score/config writes cannot alter a player's working copy.

## Keep Export And Acceptance Separate

A passing run does not update yesterday's release package. Record which source
tree, binary hashes, tests and captures belong to each checkpoint. Keep source
and redistributable code separate from privately decoded assets, page captures,
PCM, memory dumps and proprietary original data. Generated queue traces can
contain complete sound resources even if stored as JSON hexadecimal strings.

Use explicit export allowlists, dependency/license review and fresh-output
guards. Report remaining domains and unsupported paths instead of extrapolating
a global percentage from a selected test suite. These are engineering evidence
boundaries, not a legal opinion about redistribution rights.
