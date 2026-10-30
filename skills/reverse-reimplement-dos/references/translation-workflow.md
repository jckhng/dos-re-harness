# Plan and integrate a translation

Use this reference when starting a reimplementation or when isolated matches
accumulate without advancing continuous execution. Keep addresses, contracts,
state maps and work packages in the target project.

## Map before partitioning

Build an initial function inventory, entry points, call dependencies, resource
formats and memory map before substantial translation. Extend the map as new
paths are reached; do not demand exhaustive documentation before implementing.
Record near/far and indirect calls, interrupt entry points, shared scratch ranges
and overlapping reads/writes. Distinguish file, relocated and runtime addresses.
Static references and decompiler signatures are candidates until checked.

Group work by call dependencies and shared storage, not only by code segment or
an assumed simulation/rendering split. Preserve feedback from drawing into game
state when the original uses it. Classify runtime/library code early to avoid
rediscovering it; matches from another game are candidate names, not proof.

## Preserve storage while recovering meaning

For tightly coupled binaries, prefer canonical compatibility storage with typed
accessors over multiple persistent copies of one original location. Keep this
behind target-local domain APIs. Model hardware separately where its read/write
semantics require it. Near/far pointer identity, overlap, truncation and original
write order must survive the translation.

Move data into independently owned structures only after establishing storage,
alias and lifetime boundaries. In an existing typed implementation, first pilot
canonical storage on a proven alias problem and preserve its regression evidence;
do not trigger a wholesale rewrite. Keep the product independent of RE tools.

## Function contracts and progress

Use a compact contract for each implemented function or closely related bundle:

```text
Identity: specimen hash, source address/range, proposed name
Interface: inputs, outputs, stack/register convention, completion/trap boundary
Effects: memory ranges and aliases read/written, calls, resources, device access
Semantics: arithmetic widths, truncation, branch/update/RNG ordering
Evidence: disassembly/static references, original captures, controlled probes
Uncertainty: unproven assumptions, unsupported paths, deliberate port differences
Integration: caller, retained state, next continuous boundary, verification command
```

Track mapped, specified, implemented, integrated and validated status separately.
Validation records must name the tested cases/domains and their evidence rather
than use an unqualified boolean. Count indexed/spec'd functions as scope coverage,
not behavioural fidelity. Keep a short current ledger and link historical reports.

Build complete call paths early. Compare retained state across calls and frames;
independently reseeded fixtures do not prove carry. Temporary stubs may support
development builds only: identify them and reject reached stubs in acceptance.
Preserve a direct source-to-implementation mapping until behaviour is stable.

## Bounded agent work

Whether working alone or with authorized delegation, assign:

- owned functions/files and established interface dependencies;
- the relevant source/specification bundle and unresolved question;
- the integration boundary to advance;
- the smallest original/native experiment that can reject a wrong interpretation;
- verification commands and a compact report of evidence, gaps and interface requests.

When delegation is authorized, keep one owner per file/interface and a coordinator
for cross-module changes. Use separate build directories when needed. Save each
completed contract incrementally; do not leave essential discoveries only in a
worker's context. Avoid nested delegation that duplicates ownership or loses work
when a parent stops. More agents are not a substitute for defined dependencies.

## Fidelity and iteration cost

State the project's acceptance domains explicitly: semantics, retained execution,
indexed pixels/palette, temporal presentation, audio and hardware scheduling.
Implementing a path and certifying it are separate milestones. Unqualified paths
may be explored but cannot satisfy a stricter accepted goal. Never replace exact
hardware scheduling with host polling or fitted timing without an explicit scope
change. Unicorn instruction counts are not elapsed CPU/device time.

Reuse qualified original captures for native iterations. Batch related probes,
run focused regressions and retain a negative control. Measure launch, execution,
transfer, comparison and archival costs before optimizing them. If successive
iterations neither advance an integrated boundary nor resolve a named prerequisite,
inspect the architecture, shared state or harness before expanding the probe campaign.

Use existing harness commands before writing another wrapper. `capture-plan`
packages capture requests; `run-plan` records native execution; `probe-plan` runs
bounded CPU fixtures; `evidence-status` derives status from declared dependencies.
The read-only Ghidra program index seeds mapped-only progress inventories. See
[workbench contracts](../../../docs/workbench.md) for schemas and qualification
limits. Persistent sessions remain planned; owners/device interpretation stay local.

Keep playable integration and strict certification as separate declared gates
when the task distinguishes them. Preflight dependencies before expensive runs;
run affected checks during a batch and full acceptance at joined milestones.
Integrate a complete operation and retained successor before expanding isolated
coverage. Never change an accepted fidelity requirement to make a milestone pass.
