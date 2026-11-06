# Start a DOS reverse/reimplementation project

Aim first for a reproducible original run and one compared native behavior.
You do not need to understand the whole executable first.

## 1. Install tools for the next step

From a checkout, with Python 3.8+ and Git installed:

```text
python -m pip install -e .
dos-re --help
```

Use **DOSBox-X** for original execution. Captures require the
[pinned remotedebug build](../backends/dosbox-x-remotedebug/README.md), which adds
the required RSP/QMP operations. Classic DOSBox and stock DOSBox-X do not supply
the same capture contract.

The current capture adapter uses PowerShell and WSL2. Follow
[backend setup](usage-reference.md#capture-backend-setup) to install the WSL
build dependencies, then build and select the pinned executable:

```powershell
.\scripts\prepare-wsl-backend.ps1 -Build
New-Item -ItemType Directory -Force .work\backend-bin | Out-Null
Copy-Item .work\dosbox-x-remotedebug\src\dosbox-x .work\backend-bin\dosbox-x
```

For an existing checkout, inspect its backend lock, executable and qualification
records before rebuilding or replacing it. If the backend is unavailable,
resolve setup explicitly; do not silently substitute another emulator.

Add Ghidra for code queries, Unicorn for bounded CPU comparisons, and a C/C++
compiler, CMake and SDL2 when building the native program. These are separate
from the Python core. See [tool setup](usage-reference.md#dependencies).

## 2. Keep the specimen private and fixed

Create this structure for a new target:

```text
projects/<target>/
  project.json             paths, runtime schema and capture adapter
  scenarios.json           named input/capture scenarios
  tools/                   target-specific discovery and decoding
  reimplementation/        independent native program
  .work/                   ignored local data
    specimen/              exact original executable and data files
    captures/              fresh directory per run
    analysis/              private disassembly and experiments
```

Record the release, file hashes, emulator settings and mutable files such as
saves and configuration. Run from a clean writable copy, preserving the specimen.
Renaming an example manifest is insufficient: memory layouts, input gates and
display formats belong to each target's adapter.

## 3. Establish the first capture

The repository includes a reviewed [Paku Paku adapter](../projects/pakupaku/README.md).
Place the exact Paku Paku 1.6 files listed in its specimen manifest under
`projects/pakupaku/.work/specimen/paku-1.6`, then run:

```powershell
.\projects\pakupaku\verify-specimen.ps1
dos-re doctor projects/pakupaku/project.json
dos-re capture projects/pakupaku/project.json first-movement --out-dir projects/pakupaku/.work/captures/first-movement-01 --dry-run
```

Review the resolved command, then repeat without `--dry-run`. Use a new output
directory each time. `doctor` checks declared tools/capabilities, not actual
emulator behavior or target fidelity. Example native build/run commands are in
the [usage reference](usage-reference.md).

For a new game or application, use the prompt in the [README](../README.md). Run
the original in DOSBox-X and locate a repeatable interactive boundary. Define a small
state schema and gate input on observed state, not host sleeps. Packed programs
may need a private unpacked analysis copy; capture the original. Protected-mode
programs need descriptor-based addresses rather than `selector << 4`.

## 4. Close one comparison loop

1. Recover a small behavior and its inputs/outputs from code and runtime evidence.
2. Capture the original at a known boundary.
3. Implement the behavior and emit comparable native state.
4. Compare state and indexed pixels/palette; investigate the first divergence.
5. Retain a regression and connect the behavior to the next continuous route.

A useful early route is startup → menu/input → one interactive operation. For
a game, that might extend to mission selection and one playable frame; for an
application, opening a document or executing a command. Keep platform I/O in a
host layer so the core can run headlessly and support another host later.

Use [capture plans](capture-plans.md) for repeated captures and the
[workbench](workbench.md) for command receipts, CPU fixtures and evidence status.
Frame matches do not prove cadence; sound-register matches do not prove mixed
waveforms; bounded CPU results do not prove IRQ/device scheduling. Track these
limits instead of treating a playable build as full parity.
