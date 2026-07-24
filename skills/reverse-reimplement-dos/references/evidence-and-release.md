# Evidence, Checkpoints, and Release Boundaries

## Evidence Manifest

Record for every original capture:

- project and scenario identifiers;
- pristine specimen manifest hash;
- mutable-file baseline hashes;
- backend source commit and patch hash;
- emulator configuration;
- state schema, screen signatures, and input movie hashes;
- capture command;
- registers and segment selection;
- artifact hashes;
- repository commit;
- exit status and timestamp.

Do not treat an unmanifested capture as durable evidence.

## Checkpoints

Create checkpoints at reproducible knowledge transitions:

```text
00 harness bootstrap
01 specimen and first original capture
02 first matching state trace
03 first matching indexed frame
04 first matching temporal presenter
05 audio routing and lifetime parity
06 portable compatibility milestone
```

Each checkpoint should state:

- objective;
- evidence added;
- exact reproduction command;
- first remaining divergence;
- known harness limitations;
- rights and redistribution boundary.

Use ordinary commits and annotated tags. Do not manufacture historical
granularity after the work is complete.

## Public Repository Boundary

Keep the reusable harness target-neutral. A target repository owns:

- executable and data locations;
- specimen hashes;
- state schema;
- screen signatures;
- memory addresses and patches;
- input movies and warps;
- target-specific Ghidra symbols;
- reimplementation source.

The public harness owns:

- schema and movie formats;
- backend capability contracts;
- generic remote-control client;
- trace/frame/audio comparison;
- evidence manifest format;
- synthetic or freely redistributable fixtures;
- reusable agent skill.

Run a conservative public-tree audit before the first commit and before each
release. Review Git history as well as the current tree.

## Licensing

Use separate notices for:

- original harness code;
- emulator-derived patches;
- bundled example source;
- generated or recovered target material.

Do not imply that a permissive harness license covers GPL-derived backend
patches. If distributing a patched emulator executable, satisfy its
corresponding-source obligations.

Do not publish proprietary binaries, extracted resources, screenshots, audio,
framebuffers, memory dumps, save states, or Ghidra databases without a
separate rights basis and review.

## Reimplementation Distribution

When original data cannot be redistributed:

1. publish source and independently authored binaries;
2. require the user to provide a legally obtained original installation;
3. verify required files by supported hashes or format checks;
4. import/decode data locally at first run or through a documented tool;
5. keep imported assets outside source packages and release archives.

The released product must run without the reverse-engineering harness.
