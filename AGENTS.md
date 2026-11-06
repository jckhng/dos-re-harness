# Working in DOS RE Harness

- Use **DOSBox-X** to run DOS originals. For automated capture, use the pinned,
  patched DOSBox-X remotedebug backend in `backends/dosbox-x-remotedebug/`.
  Do not substitute classic DOSBox, DOSBox Staging or an unqualified stock
  DOSBox-X build when the required backend is missing. Report the missing
  dependency and follow the backend setup guide.
- Read `skills/reverse-reimplement-dos/SKILL.md` for reverse/reimplementation
  work. Start a new target with `docs/getting-started.md`.
- Keep target behavior, addresses and formats in `projects/<target>/`.
  Keep originals, extracted assets, captures and build outputs under `.work/`.
  Promote only target-neutral code with synthetic tests into the harness.
- Ghidra supports static analysis; Unicorn supports bounded CPU experiments.
  Neither replaces DOSBox-X for device behavior or continuous runtime timing.
- Keep the portable reimplementation independent of the harness and emulator.
  Preserve existing project conventions and unrelated working changes.
