# DOS RE Harness

State-gated original-binary capture and differential validation for DOS
software reimplementations.

The harness treats the running original executable as the behavioral
specification. It combines:

- DOSBox-X remote control through GDB RSP and QMP;
- scripted keyboard input, memory pokes, register restoration, and function
  warps;
- one-process state and repeated-breakpoint checkpoint series;
- schema-driven process-memory capture;
- indexed VGA framebuffer, DAC palette, and temporal sequence capture;
- WAV/OPL capture through the emulator backend;
- specimen hashes and auditable capture artifacts;
- Ghidra headless function, instruction, xref, and scalar queries;
- field-level state comparison and adapter hooks for trace, image, audio, and
  side-by-side temporal comparison.

The toolkit does not include proprietary game binaries, assets, or captures.
Third-party components and patches are listed in `THIRD_PARTY_NOTICES.md`.

## Architecture

The harness has three separate layers:

- The Python core is host-neutral. Manifests, schemas, movies, state parsing,
  trace comparison, raw framebuffer comparison, and evidence metadata run on
  Windows or Linux.
- Capture backends are replaceable host adapters. The current proven adapter
  starts a patched DOSBox-X build under WSL2 from PowerShell.
- A reimplementation is a separate product. It must build and run without WSL,
  DOSBox-X, Ghidra, or this harness.

The current Windows/WSL arrangement is deliberate. Windows owns the repository,
native build, and analysis tools; WSL runs the remotedebug backend whose GDB and
QMP behavior has already been validated. A future native-Windows or native-Linux
backend can replace it by declaring and passing the same capability contract.

## Portability Contract

Example reimplementations should:

- use portable C or C++ with SDL and CMake;
- isolate OS integration behind narrow platform adapters;
- keep gameplay, timing, input interpretation, rendering, and asset decoding
  free of Win32 dependencies;
- build in both Windows and Linux CI;
- load legally obtained original data at runtime when redistribution is not
  permitted;
- avoid requiring the reverse-engineering harness at runtime.

## Layout

```text
src/dos_re_harness/       Generic Python capture and comparison core
scripts/                  PowerShell and POSIX entry points
ghidra/scripts/           Target-independent Ghidra headless queries
backends/                 Emulator patches and backend documentation
docs/                     Workflow and example-project plans
skills/                   Reusable agent workflow
tests/                    Contract tests and a synthetic project fixture
projects/pakupaku/        Reviewed binary-only end-to-end example
```

Target adapters normally belong in their target repositories. Paku Paku is
included here as a reviewed reference case; its specimen, captures, Ghidra
database, backend binary, and build products remain under ignored `.work/`
directories.

## Agent Skill

`skills/reverse-reimplement-dos/SKILL.md` packages the evidence-first workflow
for Codex-compatible agents. It covers specimen control, static/runtime
analysis, asset and audio recovery, deterministic capture, presenter
choreography, differential validation, portability, and public checkpoints.

Install or reference that skill when beginning a DOS reverse-engineering or
faithful reimplementation task. Keep addresses, resource IDs, specimens, and
target-specific conclusions in the target repository rather than modifying the
generic skill.

## Agent-Guided Example: Paku Paku

Run the agent from the repository root so it can read the skill, generic
harness, backend lock, and example adapter.

`projects/pakupaku/` is the tracked project adapter, not the directory for the
original game installation. Original files must be nested under its ignored
`.work/specimen/` directory:

```text
projects/
  pakupaku/                         tracked: commit this project
    project.json
    scenarios.json
    reimplementation/
    .work/                          private and ignored: do not commit
      specimen/
        paku-1.6/                   original game files go here
          PAKU.EXE
          FONTS.DAT
          MAP.DAT
          ...
```

Do not copy original executables or data files directly into
`projects/pakupaku/`. First place the exact legally obtained Paku Paku 1.6
files listed in `projects/pakupaku/specimen-manifest.json` under the ignored
specimen path:

```powershell
New-Item -ItemType Directory -Force `
  projects\pakupaku\.work\specimen\paku-1.6 | Out-Null
Copy-Item C:\path\to\paku-1.6\* `
  projects\pakupaku\.work\specimen\paku-1.6
pwsh -NoProfile -File projects\pakupaku\verify-specimen.ps1
```

Do not place the specimen elsewhere in the tracked tree. Verification rejects
missing, modified, and unexpected files, including a pre-existing mutable
`SCORES.DAT`. Complete the Core Setup and Capture Backend Setup below before
running an original-binary capture. Install Ghidra only when static analysis is
needed.

Give a Codex-compatible coding agent this initial instruction:

```text
Read and use skills/reverse-reimplement-dos/SKILL.md. Work from the private,
verified Paku Paku 1.6 specimen in
projects/pakupaku/.work/specimen/paku-1.6. Use the pinned DOSBox-X capture
backend and target-local Ghidra analysis. Do not search for or consult Paku
Paku source code; treat the executable and runtime captures as the behavioral
specification. Keep specimens, captures, extracted assets, memory dumps,
backend binaries, build products, and Ghidra databases under .work. Keep all
Paku-specific code under projects/pakupaku and modify the generic harness core
only when a genuinely reusable capability is missing. Continue from the
documented checkpoints, add regression evidence before behavior changes, and
work toward a portable interactive reimplementation.
```

For a new target, replace the name and specimen path, create
`projects/<target>/`, and retain the same evidence and publication boundaries.
Tell the agent the local Ghidra headless launcher path when static analysis is
needed, for example:

```text
Ghidra headless launcher:
C:\Tools\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat
```

Check the adapter and capture a durable original-binary checkpoint:

```powershell
.\scripts\dos-re.ps1 doctor projects\pakupaku\project.json
.\scripts\dos-re.ps1 capture `
  projects\pakupaku\project.json first-movement `
  --out-dir projects\pakupaku\.work\captures\first-movement
```

Build, test, and run the independent Windows reimplementation:

```powershell
cmake -S projects\pakupaku\reimplementation `
  -B projects\pakupaku\.work\build
cmake --build projects\pakupaku\.work\build --config Release
ctest --test-dir projects\pakupaku\.work\build `
  -C Release --output-on-failure
projects\pakupaku\.work\build\Release\pakupaku_play.exe `
  --data projects\pakupaku\.work\specimen\paku-1.6 `
  --scale 6
```

The capture command uses DOSBox-X and the harness backend. The resulting
`pakupaku_play.exe` does not; it is a separate native program that reads the
user-supplied, hash-verified data files.

## Dependencies

The harness core has no third-party Python runtime dependencies. Install only
the layers needed for the work being performed.

### Dependency Acquisition Policy

DOSBox-X and Ghidra are intentionally not Git submodules:

- The DOSBox-X backend is optional, GPL-2.0-only, built under WSL, and pinned
  by upstream URL, commit, and verified patch hash in
  `backends/dosbox-x-remotedebug/backend.lock.json`. The preparation script
  downloads it only when capture work requires it.
- Ghidra is optional, distributed as a versioned binary release, requires a
  compatible JDK, and is invoked through an explicit local
  `analyzeHeadless` path. A source submodule would not reproduce the tested
  binary distribution or the host Java installation.

A normal clone therefore remains small and usable for manifest validation and
portable comparison. Capturing an original binary requires the documented
host setup. Submodules would still require `--recurse-submodules`, network
access, WSL packages, Java, and local path configuration, while coupling
optional tools and mixed licenses to every checkout.

### Tested Baseline

| Component | Known-good version | Supported baseline |
| --- | --- | --- |
| Python on Windows | 3.11.0 | 3.8 minimum; 3.11 or newer recommended |
| Python in WSL | 3.8.10 | 3.8 minimum |
| Git | 2.45.1 | Git 2.x |
| PowerShell | Windows PowerShell 5.1 and PowerShell 7.6.2 | 5.1 minimum; PowerShell 7.4 or newer recommended |
| Ghidra | 12.0.3 | 12.1.2 recommended for a new installation |
| Java | Amazon Corretto 21.0.10 | 64-bit JDK 21 |
| Capture host | WSL2 with Ubuntu 20.04.6 LTS | WSL2 with a compatible Linux distribution |
| Backend toolchain | GCC 9.4.0 and GNU Make 4.2.1 | C++11-capable GCC or Clang and Make |

These are reproducibility baselines, not requirements to install every listed
tool. Windows owns the normal checkout and native development workflow. WSL is
needed only by the current original-binary capture backend.

### Core Setup

Install:

- [Python](https://www.python.org/downloads/), version 3.8 or newer;
- [Git](https://git-scm.com/downloads), version 2.x;
- [PowerShell](https://learn.microsoft.com/powershell/scripting/install/install-powershell-on-windows),
  preferably the current stable PowerShell 7 release on Windows.

Create an isolated environment and install the command-line entry point:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
dos-re validate-project tests\fixtures\minimal-project\project.json
```

On Linux or WSL:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
dos-re validate-project tests/fixtures/minimal-project/project.json
```

An editable package installation is convenient but not mandatory. The
`scripts/dos-re.ps1` and `scripts/dos-re` launchers run directly from a
checkout.

### Ghidra Setup

Ghidra is required only for static analysis and headless queries. It is not
needed for capture comparison or for a finished reimplementation.

1. Install a 64-bit JDK 21, such as
   [Eclipse Temurin 21](https://adoptium.net/temurin/releases/?version=21).
2. Download the binary release ZIP for
   [Ghidra 12.1.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.2_build).
   Use the release asset, not GitHub's automatically generated source archive.
3. Extract Ghidra to a stable, versioned directory, such as
   `C:\Tools\ghidra_12.1.2_PUBLIC`.
4. Import and analyze the target executable once in a Ghidra project.
5. Pass the path to `support\analyzeHeadless.bat` to the harness wrapper.

For a 16-bit DOS real-mode executable, begin with the Ghidra language
`x86:LE:16:Real Mode`, then verify the loader result against runtime addresses.
The repository's known-good analysis environment is Ghidra 12.0.3 with JDK 21;
12.1.2 is the current recommended baseline for a new setup. The official
[Ghidra repository](https://github.com/NationalSecurityAgency/ghidra) contains
the complete installation notes.

Example headless query:

```powershell
$ghidraHeadless = 'C:\Tools\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat'
.\scripts\ghidra-query.ps1 `
    -Query programs `
    -GhidraHeadless $ghidraHeadless `
    -ProjectDir C:\Analysis\ghidra `
    -ProjectName target `
    -Program TARGET.EXE
```

Use `.\scripts\ghidra-query.ps1 -?` for all query and evidence-output options.

Target adapters can run checked-in target-local scripts through the same
isolated runtime and write evidence atomically:

```powershell
.\scripts\ghidra-query.ps1 `
    -Query custom `
    -CustomScript DecompileAt.java `
    -AdditionalScriptPath projects\target\tools\ghidra `
    -GhidraHeadless $ghidraHeadless `
    -ProjectDir projects\target\.work\ghidra `
    -ProjectName target `
    -Program GAME.UNPACKED.EXE `
    -TempRoot projects\target\.work\ghidra-runtime `
    -NoAnalysis `
    -OutputPath projects\target\.work\analysis\function.txt `
    -Args 1000:1234
```

`-OutputPath` writes through a `.partial` file, refuses to overwrite existing
evidence, and publishes the final file only after a successful non-empty
query. `-NoAnalysis` queries the existing database without repeating automatic
analysis. `-JavaHome` pins a JDK when the isolated Ghidra profile does not
already record one.

### Capture Backend Setup

The current capture backend uses a pinned, patched DOSBox-X build inside WSL2.
Stock DOSBox-X does not expose the complete remote-debug capability contract
required by the harness.

Install [WSL2](https://learn.microsoft.com/windows/wsl/install) from an
administrator terminal, then install or select an Ubuntu distribution:

```powershell
wsl --install
wsl --list --verbose
```

The backend is proven on Ubuntu 20.04.6 LTS. A newer distribution should work,
but must pass the backend smoke tests before being treated as a reproducible
capture environment.

Install the DOSBox-X build dependencies inside Ubuntu:

```sh
sudo apt update
sudo apt install \
    build-essential autoconf automake libtool pkg-config nasm \
    libncurses-dev libsdl2-dev libsdl2-net-dev libpcap-dev \
    libslirp-dev fluidsynth libfluidsynth-dev \
    libavdevice-dev libavformat-dev libavcodec-dev libswscale-dev \
    libfreetype6-dev libxkbfile-dev libxrandr-dev
```

Build and install the pinned backend from the Windows checkout:

```powershell
.\scripts\prepare-wsl-backend.ps1 -Build
New-Item -ItemType Directory -Force .work\backend-bin | Out-Null
Copy-Item .work\dosbox-x-remotedebug\src\dosbox-x `
  .work\backend-bin\dosbox-x
.\scripts\dos-re.ps1 doctor tests\fixtures\minimal-project\project.json
```

The source revision, patches, and expected hashes are recorded under
`backends/dosbox-x-remotedebug/`. If a patched backend binary is distributed,
follow the corresponding-source obligations recorded in
`THIRD_PARTY_NOTICES.md`.

### MCP

[Model Context Protocol](https://modelcontextprotocol.io/docs/getting-started/intro)
is not a harness dependency. The supported Ghidra integration invokes
`analyzeHeadless` and the checked-in Java scripts directly, which is
deterministic, scriptable, and usable without an agent.

No Ghidra MCP server is currently pinned or tested by this repository. An MCP
server may be added locally for interactive navigation, but evidence needed for
reproduction should still be emitted by the headless query scripts and stored
in the target repository.

### Optional Tools

- `dbxdebug` is optional; the harness includes its own remote controller.
- `mzexplode` is optional for statically analyzing packed DOS MZ executables.
  The harness records the tool, input, and output hashes:

  ```powershell
  pwsh -NoProfile -File scripts/dos-re.ps1 unpack-mz `
    projects\target\.work\specimen\release\GAME.EXE `
    projects\target\.work\unpacked\GAME.UNPACKED.EXE `
    --tool /absolute/path/to/mzexplode `
    --wsl-distribution Ubuntu
  ```

  Capture the pristine packed executable. Use the unpacked derivative only for
  private static analysis and keep it under `.work`.
- [Pillow](https://pypi.org/project/pillow/) is optional for convenience image
  conversion; indexed framebuffer comparison does not require it.
- [CMake](https://cmake.org/download/) and
  [SDL](https://wiki.libsdl.org/SDL3/FrontPage) are reimplementation build
  dependencies, not harness dependencies. Each target repository should pin
  the versions it supports.

Verify a complete local setup:

```powershell
python --version
git --version
java -version
wsl --list --verbose
.\tests\run.ps1
.\scripts\dos-re.ps1 audit-public-tree .
```

## Quick Check

From the toolkit directory:

```powershell
.\scripts\dos-re.ps1 `
    validate-project `
    tests\fixtures\minimal-project\project.json
```

Expected output:

```text
VALID project=minimal-fixture fields=2 scenarios=1
```

On Linux or WSL:

```sh
sh scripts/dos-re \
    validate-project \
    tests/fixtures/minimal-project/project.json
```

After installing the package, use the same `dos-re` command on either host.

Check the selected adapter and host dependencies:

```powershell
.\scripts\dos-re.ps1 doctor `
    tests\fixtures\minimal-project\project.json
```

Audit a proposed public toolkit tree for executable formats, audiovisual
captures, target data, generated files, oversized files, and personal paths:

```powershell
.\scripts\dos-re.ps1 audit-public-tree .
```

Inspect a capture command without starting DOSBox-X:

```powershell
.\scripts\dos-re.ps1 `
    capture `
    tests\fixtures\minimal-project\project.json `
    boot `
    --out-dir .work\fixture-capture `
    --dry-run
```

Run the capture by removing `--dry-run`.

Inspect a capture without loading its full register metadata:

```powershell
dos-re summarize-capture `
    projects\example\.work\captures\gameplay
```

Add `--json` for compact structured output or `--out PATH` to write
`capture_summary.json`. Large embedded input scripts and checkpoint states are
represented by counts and SHA-256 identities; the original evidence remains
unchanged. PCM WAV files below the capture directory are indexed with their
hash, format, duration, peak, DC offset, RMS, and per-channel metrics.

Capture-adapter configuration values and scenario arguments can be overridden
without editing a tracked scenario:

```powershell
.\scripts\dos-re.ps1 capture projects\example\project.json gameplay `
    --out-dir projects\example\.work\captures\resumed `
    --adapter-argument "poke_file=ds:0:C:\path\state.bin" `
    --adapter-argument "resume_checkpoint_script=checkpointstatescriptfile:0x850c:tick:100+110:72"
```

Each `NAME` must already be declared in the adapter `configuration` or the
selected scenario's `arguments`. Command-line values override scenario values,
which override adapter defaults. The rendered command records the effective
values in the evidence manifest.

Preflight a changed state-input-script tail before starting DOSBox-X:

```powershell
.\scripts\dos-re.ps1 plan-state-tail `
    projects\example\project.json gameplay `
    --previous-input-script projects\example\.work\routes\v1.input.script `
    --input-script projects\example\.work\routes\v2.input.script `
    --resume-from projects\example\.work\captures\prior\checkpoints\tick-500 `
    --checkpoint-value 500 --end-value 650 `
    --state-field tick --breakpoint 0x850c `
    --movie projects\example\.work\movies\resume.movie.json `
    --capture-out projects\example\.work\captures\tail-v2 `
    --transition-breakpoint 0x1234:0x5678 `
    --transition-out projects\example\.work\captures\tail-v2-transition `
    --out projects\example\.work\plans\tail-v2.json
```

The planner does not launch the backend. It validates the project, scenario,
scripts, tick-1 bootstrap movie, snapshot dump size, registers, output-path
freshness, adapter argument names, and transition address. Its JSON records
the first input-state difference and ready-to-run `capture_cli_args` for the
continuous tail and optional transition probe. Pass `--allow-existing-output`
only when intentionally reusing retained evidence.

## Generic State Tools

Decode a memory dump:

```powershell
.\dos-re-harness\scripts\dos-re.ps1 parse-state `
    --schema projects\example\state.schema.json `
    --dump captures\original\state.bin `
    --out captures\original\state.json
```

Compare original and reimplementation state:

```powershell
.\dos-re-harness\scripts\dos-re.ps1 diff-state `
    --schema projects\example\state.schema.json `
    --original captures\original\state.json `
    --reimplementation captures\reimpl\state.json `
    --strict
```

Supported field types are `u8`, `s8`, `u16le`, `s16le`, `u32le`, and
`s32le`. Repeated structures can be declared as block templates with named
base-address instances.

## Project Adapter

A project directory contains:

```text
project.json
state.schema.json
screens.json
scenarios.json
```

These tracked adapter files belong under `projects/<target>/`. Private
original files belong under
`projects/<target>/.work/specimen/<version>/`, never directly in the tracked
project directory.

`project.json` records specimen inputs, executable and mount settings, memory
and VGA layout, Ghidra metadata, scenarios, and the capture adapter command.
An adapter can declare `backend_lock` and a JSON `configuration` object. A
non-dry capture then records the locked upstream commit, verified patch hash,
emulator settings, memory/framebuffer selection, and mutable-file baseline in
`harness_manifest.json`.

`state.schema.json` assigns stable names and types to offsets in a captured
segment. These fields form the original/reimplementation state contract.

`screens.json` classifies raw indexed framebuffers using ordered region hashes
or measurable constraints. Scenario actions can then use
`waitvga:<state>`, `waitnotvga:<state>`, and `drivevga:<state>`.
`waitvga` and `waitnotvga` accept an optional polling interval as
`waitvga:<state>:<timeout>:<interval>` when a sub-frame gate is needed.
Controlled runtime experiments can use
`poke:<linear-address>:<hexbytes>`; the controller halts, writes, and resumes
atomically. Target checkpoints must record the pristine hash, patch bytes,
address, entry state, and bypassed behavior.
`breaknth:<linear-address>:<positive-hit-count>` leaves execution stopped on a
specific invocation of shared code, permitting stable capture of repeated
render or update calls.
`breakstate:<linear-address>:<field-predicate>:<positive-maximum-hit-count>`
checks the selected dump segment against `state.schema.json` on every
breakpoint hit and stops only when the predicate matches. The maximum hit
count makes a missing logical boundary fail explicitly instead of hanging or
silently capturing a nearby state.
`checkpointstate:<linear-address>:<field>:<value>[+<value>...]:<positive-maximum-hit-count>`
captures a complete memory, register, and VGA checkpoint for each requested
schema value during one emulator run. Values must be unique and are matched in
the declared order. Checkpoints are written below
`checkpoints/<field>-<value>/`; the parent evidence manifest recursively hashes
every nested artifact. Breakpoint predicates read only the declared schema
field bytes through RSP on intermediate hits; complete segment, low-memory,
VGA, DAC, and register dumps are still retained for each selected checkpoint.
Use `-OmitCheckpointVga` when nested checkpoints are semantic-state evidence
only. It retains the final root VGA capture but omits per-checkpoint VGA dumps,
and records null VGA artifacts in checkpoint metadata.
Use `-CheckpointScreenshot` to request a QMP screenshot while execution is
halted at each selected checkpoint. Each nested checkpoint records the PNG or
the nonfatal screenshot error alongside its memory and register evidence. If
the backend writes a PNG only after a timed-out request resumes, the harness
retains it as a deferred side effect with
`screenshot_exact_checkpoint: false`; it is not state-aligned regression
evidence.
Timed VGA sequences retain both the indexed framebuffer and the 256-entry DAC
palette for every sample. Each row in `vga_sequence.json` records independent
hashes and change counts for pixels and palette bytes, so palette-only fades,
flashes, and cycling remain observable even when framebuffer memory is static.
Use `-CheckpointSaveState` only when the final startup action is a state
checkpoint. It writes `remote_runtime.sav` beside that checkpoint and records
its size, SHA-256, request boundary, post-save registers, and post-save schema
state. Unlike a segment dump, the DOSBox-X state includes CPU, RAM, VGA
planes/pages and registers, and the DAC palette. The controller briefly
releases the stopped CPU because DOSBox-X cannot service a save request while
its GDB loop is halted.
Load that artifact with `-LoadSaveState`. The companion
`remote_runtime_registers.json` is mandatory and its saved-state hash is
verified before load. `-LoadSaveStateReadyScreen` gates the load on a
classified guest screen so DOSBox-X has completed normal initialization.
Save/load requests are asynchronous: execution can move between the requested
checkpoint and the actual saved or reattached state. Input-script resume
accepts that drift only when it proves that no input event was crossed.
Save states are pinned-backend/configuration accelerators, not portable
behavioral evidence or substitutes for a natural-reachability capture. Store
them below the target's `.work` tree and create them sparsely at neutral,
high-value boundaries.
`--resume-checkpoint-script` continues from the current halted state, with or
without target-controlled state-file pokes. It accepts either a neutral
`checkpointstate:<linear-address>:<field>:<value>[+<value>...]:<maximum-hits>`
action or the input-driven `checkpointstatescriptfile` form. The first value
must already match the current or restored schema state. If a resumed value
reuses an existing startup-checkpoint name, it is written below
`checkpoints/resume/` instead of overwriting or colliding with that evidence.
The file-backed form discards earlier input events only
after proving that no key is held across the resume boundary. The target must
also supply `--resume-next-linear`, and its bootstrap movie must clear the
original breakpoint and stop at that statically verified next instruction.
Full register restoration is intentionally rejected in this mode because the
pinned DOSBox-X backend cannot continue reliably after its RSP full-register
write. This is a controlled state resume, not a general emulator save-state
format.
`--post-resume-break-linear` continues from the final resumed state boundary
to a function or instruction breakpoint. Use
`--post-resume-break-segmented <segment>:<offset>` for a real-mode far-code
breakpoint whose backend address must retain both components. Pair either with
`--post-resume-break-hit-count` to stop on a specific repeated invocation.
Use `--post-resume-break-hit-series 2,9,17,31` instead when several invocation
ordinals are required. The CPU advances once to the largest ordinal and writes
each requested hit below `checkpoints/breakpoint_hit-<hit>/`, avoiding one
DOSBox-X startup per ordinal. Series values must be positive and strictly
increasing. Every selected hit retains the VGA DAC as well as the indexed
framebuffer. A series is read-only and cannot be combined with post-resume
poke files or the staged next-breakpoint path.
The controller arms this breakpoint only after restoration and removes the
state-boundary breakpoint first when the resume script advanced through more
than one state. This avoids replaying startup solely to inspect code reached
from an already verified checkpoint.
After that first post-resume stop,
`--post-resume-poke <linear>:<hexbytes>` and
`--post-resume-poke-file <linear>:<path>` can apply one or more file-backed
or inline memory writes while the CPU remains halted. Pair them with
`--post-resume-next-break-linear` or
`--post-resume-next-break-segmented <segment>:<offset>` and
`--post-resume-next-break-hit-count` to step off the first breakpoint and
stop at a later instruction. The second breakpoint is also valid without a
poke, which supports entry-to-exit captures inside one function invocation.
Use `--post-resume-continue-after-poke` instead when the write creates a
controlled running state for a timed VGA or screenshot sequence and no second
breakpoint is required.
Metadata records each poke's resolved address, byte count, and SHA-256, plus
both breakpoint selections.
`clearbreak:<linear-address>` removes a halted linear breakpoint, single-steps
past it, and records the resulting halted registers, allowing a state
checkpoint to chain into a later segmented or linear breakpoint.
`removebreak:<linear-address>` removes a halted linear breakpoint without
executing the trapped instruction. This supports controlled capture warps that
must replace or inspect the instruction at the exact stopped boundary.
`removebreakso:<segment>:<offset>` performs the same no-step removal using the
backend's packed real-mode breakpoint address.
`pokehalted:<linear-address>:<hexbytes>` writes memory while the CPU is
already halted and resumes without issuing a redundant halt request. It can be
combined with `removebreak` to replace the trapped instruction for a
documented test-only warp.
`continuebreakso:<segment>:<offset>` installs a segmented breakpoint while
the CPU is already halted and resumes toward it without issuing another halt
request.
`breakwaithaltedso:<segment>:<offset>` performs the same halted-to-running
transition, waits for the target breakpoint, and verifies that the reported
physical EIP equals the requested real-mode address. It replaces any earlier
halted registers so the final capture cannot silently reuse a preceding
checkpoint.
For backends whose execution-breakpoint API consumes a real-mode logical
address, `breakso:<segment>:<offset>` packs the two 16-bit components without
assuming that the packet accepts a physical linear address.
`breaksonth:<segment>:<offset>:<positive-hit-count>` combines that packed
address form with deterministic nth-hit stopping.
`runfor:<positive-seconds>` resumes an already halted guest for a bounded
host duration and re-halts it. This is intended for cleanup after an exact
checkpoint, such as allowing a DOS program to exit and finalize native
capture files; it is not an emulated-tick synchronization primitive.

The generic WSL launcher also accepts `-CaptureVideo`. It wraps the configured
DOS program with DOSBox-X `DX-CAPTURE /V`, leaving the resulting native AVI in
the capture directory where the ordinary evidence manifest hashes it. Targets
must still provide an explicit post-checkpoint exit path so the AVI is
finalized. Declare this backend feature as `video.capture`.

`scenarios.json` contains deterministic startup actions, state predicates, and
adapter arguments. Reusable actions can be placed in a versioned
`*.movie.json` file and referenced with `input_movie`. Game-specific patch
points and scene choreography belong here or in a target adapter, never in the
core.

Movies are currently state-gated action scripts. State and screen waits remove
most host scheduling variance, but duration-based key holds still use backend
time. Emulated-tick input recording and replay is a remaining hardening task.

Scenarios declare backend requirements such as `memory.read`,
`input.keyboard`, or `screen.sequence`. `validate-project` rejects a scenario
when the selected adapter lacks a required capability.

## Portable Comparison

Find the first divergent JSONL trace row:

```powershell
.\dos-re-harness\scripts\dos-re.ps1 diff-trace `
    captures\original\trace.jsonl `
    captures\reimpl\trace.jsonl
```

Compare two raw 320x200 indexed framebuffers and write a PGM difference image:

```powershell
.\dos-re-harness\scripts\dos-re.ps1 diff-frame `
    --expected captures\original\vga.bin `
    --actual captures\reimpl\vga.bin `
    --width 320 `
    --height 200 `
    --json captures\diff.json `
    --diff captures\diff.pgm
```

Inspect a PCM WAV without adding an audio dependency:

```powershell
.\dos-re-harness\scripts\dos-re.ps1 inspect-wave `
    captures\original\program_000.wav `
    --out captures\original\program_000.wave.json
```

Compare original and portable PCM. The default is exact, frame-aligned sample
comparison. Explicit mixdown, sample tolerance, and leading-frame skips are
available for controlled diagnostic comparisons:

```powershell
.\dos-re-harness\scripts\dos-re.ps1 diff-wave `
    captures\original\program_000.wav `
    captures\reimpl\program.wav `
    --mixdown `
    --sample-tolerance 2 `
    --out captures\audio-diff.json
```

Extract a stable register-pair stream from one-process
`breakpoint_hit-N` checkpoints. The target chooses the breakpoint and ABI;
the generic extractor masks, orders, hashes, and serializes the observed
pairs:

```powershell
.\dos-re-harness\scripts\dos-re.ps1 extract-write-trace `
    captures\original\device-writes `
    --address-register ebx `
    --value-register ecx `
    --address-mask 0xff `
    --value-mask 0xff `
    --out captures\original\device-writes.json
```

Device-specific register classification, game ticks, driver addresses, and
semantic labels remain in the target adapter.

## Ghidra Queries

```powershell
.\dos-re-harness\scripts\ghidra-query.ps1 `
    -Query decompile `
    -GhidraHeadless C:\Tools\ghidra\support\analyzeHeadless.bat `
    -ProjectDir C:\Projects\game\ghidra `
    -ProjectName game `
    -Program GAME.EXE `
    -Args '1234:5678'
```

Available queries are `decompile`, `instructions`, `xrefs`, `functions`,
`programs`, and `scalar`. Target-specific symbol renames and type fixups remain
in the target repository.

## Backend

The current backend is the patched `lokkju/dosbox-x-remotedebug` fork described
under `backends/dosbox-x-remotedebug/`.

Do not distribute a patched DOSBox-X executable alone. DOSBox-X-derived code is
GPL-2.0 and its corresponding source and license obligations remain separate
from this MIT-licensed harness.

The root MIT license does not apply to the GPL-covered backend patch. See
`THIRD_PARTY_NOTICES.md` and the backend `COPYING` file.

## Export

Because this directory does not yet have independent public history, creating a
new repository from a reviewed copy is simpler and safer than exporting the
parent repository. See `docs/publication.md`.

Before publishing it independently:

1. Add a freely redistributable example suitable for public CI. The included
   Paku Paku case requires user-provided original files and therefore cannot
   supply unattended original-binary CI captures. The examples roadmap is in
   `docs/examples-roadmap.md`.
2. Add a reproducible backend build job and corresponding-source archive.
3. Add a target-independent temporal video comparator. PCM audio inspection
   and waveform comparison are already available in the toolkit CLI.
4. Add emulated-tick input recording and replay.
5. Add native-Windows backend support only if its GDB/QMP behavior passes the
   same contract suite.

The current extraction is usable inside a target repository. Items above are
release-hardening requirements for the standalone public toolkit.
