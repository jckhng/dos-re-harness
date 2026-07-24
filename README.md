# DOS RE Harness

State-gated original-binary capture and differential validation for DOS
software reimplementations.

The harness treats the running original executable as the behavioral
specification. It combines:

- DOSBox-X remote control through GDB RSP and QMP;
- scripted keyboard input, memory pokes, register restoration, and function
  warps;
- schema-driven process-memory capture;
- indexed VGA framebuffer and temporal sequence capture;
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
3. Add target-independent temporal video and audio comparators to the toolkit
   CLI.
4. Add emulated-tick input recording and replay.
5. Add native-Windows backend support only if its GDB/QMP behavior passes the
   same contract suite.

The current extraction is usable inside a target repository. Items above are
release-hardening requirements for the standalone public toolkit.
