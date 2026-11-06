# DOS RE Harness

Reverse engineer a DOS program from its executable, then build and check an
independent portable reimplementation against the running original.

The harness helps you:

- Capture repeatable original runs: inputs, memory, registers, indexed screens,
  palettes and audio.
- Investigate routines with Ghidra and bounded Unicorn experiments.
- Compare original/native results, find the first difference and retain the
  evidence behind each implemented subsystem.

It is a toolkit, not an automatic decompiler or game converter. You supply the
original files and a target adapter. No proprietary program data is included.

## Start here

**Use DOSBox-X for DOS originals.** Automated capture requires this repository's
[pinned, patched DOSBox-X backend](backends/dosbox-x-remotedebug/README.md).
Classic DOSBox and stock DOSBox-X are not interchangeable capture backends.
The currently qualified capture setup uses PowerShell and WSL2; the Python core
and resulting native program remain separate from that host arrangement.

1. **Install the harness** with Python 3.8+ and Git, from the repository root:

   ```text
   python -m pip install -e .
   dos-re --help
   ```

2. **Choose your first target.** Follow the short
   [getting-started guide](docs/getting-started.md) for backend setup, private
   original files and the first capture. The included Paku Paku adapter provides
   a worked example; another DOS game or application needs its own adapter.

3. **Start with one visible milestone:** run the original to its first menu or
   interactive screen, capture that boundary, then reproduce and compare one small
   behavior. Expand the native route as its components become verified.

For an agent-assisted project, use this prompt after placing your original files:

```text
Use skills/reverse-reimplement-dos/SKILL.md. Work on projects/<target> using
the original files in projects/<target>/.work/specimen. Use DOSBox-X and the
pinned remotedebug backend for captures. First inspect the existing tools and
adapter, verify the specimen, run the original and capture its startup/menu.
Then reverse and reimplement one bounded behavior at a time, comparing it
against the original. Keep target-specific code in the target project and all
originals, extracted assets, captures and builds under .work. Keep the native
program portable, with platform I/O (such as SDL2) in a separate host layer.
```

## Go deeper when needed

| Need | Guide |
|---|---|
| First original run and capture | [Getting started](docs/getting-started.md) |
| Plan and integrate recovered subsystems | [Translation workflow](skills/reverse-reimplement-dos/references/translation-workflow.md) |
| Repeat experiments and track evidence | [Workbench](docs/workbench.md) · [Capture plans](docs/capture-plans.md) |
| Query code or resolve protected-mode addresses | [Ghidra](docs/ghidra-query-cookbook.md) · [Address helpers](docs/protected-mode-addressing.md) |
| Assess fidelity and remaining gaps | [Evidence boundaries](docs/evidence-boundaries.md) · [Presentation](docs/presentation-contract.md) |
| Configure tools or publish changes | [Configuration and publication](docs/configuration-and-publication.md) |
| Browse all commands and examples | [Detailed reference](docs/usage-reference.md) |

For harness development, run `python -B scripts/run_tests.py`. Core tests need
no original game, emulator, Ghidra or SDL2. Optional CPU tests use
`python -m pip install -e ".[unicorn]"`. Before committing, review the exact
staged files with `dos-re audit-public-tree --staged`.

`src/` contains reusable Python tools; `projects/` contains target adapters.
See [the reuse audit](docs/reuse-audit-2026-11-06.md),
[improvement history](docs/harness-improvement-plan.md) and
[third-party notices](THIRD_PARTY_NOTICES.md).
