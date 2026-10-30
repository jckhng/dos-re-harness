# DOS RE Harness

State-gated DOS original-binary capture and differential validation for portable
reimplementations. Keep reusable tools here and game behavior in target adapters.

The core compares state, traces, indexed pixels/palettes, ordered audio and
presentation timing. Optional Unicorn probes execute bounded CPU routines;
DOSBox-X remains the system-level oracle. Ghidra queries support static analysis.
The toolkit includes no proprietary game data or captures.

## Quickstart

Python 3.8+ and Git are sufficient for data-free tests and comparisons:

```text
python -m pip install -e .
python -B scripts/run_tests.py
dos-re --help
dos-re audit-public-tree --staged
```

PowerShell callers can use `./scripts/run-tests.ps1`. Tests need neither original
files nor DOSBox, Ghidra, SDL or a graphics SDK. Optional CPU tests use
`python -m pip install -e ".[unicorn]"` (pinned Unicorn 2.1.4).

## Choose the next operation

| Work | Entry point |
|---|---|
| Reverse/reimplement a target | [Agent skill](skills/reverse-reimplement-dos/SKILL.md) |
| Plan subsystem integration | [Translation workflow](skills/reverse-reimplement-dos/references/translation-workflow.md) |
| Run commands, CPU probes and dependency checks | [Experiment workbench](docs/workbench.md) |
| Configure local tools and review public files | [Configuration and publication](docs/configuration-and-publication.md) |
| Repeat an original capture | [Versioned capture plans](docs/capture-plans.md) |
| Inspect decompiled code/instructions | [Ghidra query cookbook](docs/ghidra-query-cookbook.md) |
| Track evidence and natural playability | [Progress accounting](docs/progress-accounting.md) |
| Compare frame/audio cadence | [Presentation contracts](docs/presentation-contract.md) |
| Understand evidence limitations | [Evidence boundaries](docs/evidence-boundaries.md) |
| Set up tools or follow Paku Paku end-to-end | [Detailed usage reference](docs/usage-reference.md) |
| Review delivered and deferred harness work | [Improvement plan](docs/harness-improvement-plan.md) |

## Keep local state private

Copy `examples/host.example.json` to ignored `.work/host.json` for machine tool
paths and environment overrides. Explicit profiles adapt portable named jobs:

```text
dos-re run-plan examples/jobs.example.json --job smoke --host-profile .work/host.json --out-dir .work/smoke-01 --dry-run
dos-re run-plan examples/jobs.example.json --job smoke --host-profile .work/host.json --out-dir .work/smoke-01
```

Only execute after reviewing the resolved command. Plans and receipts bind their
declared inputs; success does not establish fidelity. Keep private plans, profiles,
originals, extracted assets, RAM, recordings, caches and build outputs in `.work/`.
Publication checks support exact Git index blobs or an explicit file selection;
ignored files are not implicitly safe to force-add.

## Boundaries

The Python core is host-neutral. Capture backends are host adapters; the current
proven backend runs patched DOSBox-X under WSL2 from PowerShell. Ghidra and backend
setup are needed only for their respective operations. Core/optional CPU CI runs
without game data on Windows and Ubuntu 24.04.

A portable game must build and run independently of this harness, DOSBox, WSL and
Ghidra. Prefer portable C/C++, SDL and CMake with OS integration behind adapters.
Load player-supplied original data when redistribution is not permitted.

`src/` holds generic code, `scripts/` entry points, `ghidra/scripts/` static queries,
`backends/` emulator patches, `tests/` synthetic contracts and `projects/pakupaku/`
a reviewed example adapter. Target-specific addresses, formats and behavior belong
in each target project. See [third-party notices](THIRD_PARTY_NOTICES.md).
