# Paku Paku binary-only harness project

This project contains a runnable capture adapter and an independently written compatibility reimplementation checkpoint for the user-supplied Paku Paku 1.6 DOS specimen.

The analysis boundary is strict:

- `PAKU.EXE`, supplied runtime data, and bundled `README.HTM`;
- runtime observation through the harness;
- private Ghidra analysis of the supplied executable;
- no acquisition or consultation of Paku Paku source code.

## Private material

The unchanged specimen, captures, Ghidra database, backend binary, and build outputs remain under ignored `.work/` directories. Verify the specimen before capture:

```powershell
pwsh -NoProfile -File projects/pakupaku/verify-specimen.ps1
```

`SCORES.DAT` must be absent in the pristine specimen. The clean-mount adapter confines any generated score file to a private capture directory.

## Original-binary capture

The project-local adapter runs the verified executable with the pinned remotedebug DOSBox-X backend using CGA, fixed 3000 cycles, and `/speaker`. It captures the complete DS-linear 64 KiB range and raw `B800:0000` text memory.

Durable state-gated checkpoints are defined for title, READY, first movement,
and first life loss:

```powershell
pwsh -NoProfile -File scripts/dos-re.ps1 capture `
  projects/pakupaku/project.json ready `
  --out-dir C:\absolute\private\ready
```

Use scenario `first-movement` for the manifest-backed 22-update checkpoint and
`first-life-loss` for the post-collision actor-reset checkpoint.

`tools/decode_cga_text.py` converts each `0xDD` text cell into foreground/background indexed pixels. `tools/inspect_state.py` validates far pointers and decodes confirmed score, level, pellet, player, and ghost state.

## Reimplementation

The portable C++17/CMake core is under `reimplementation/`. It verifies user-provided asset hashes and currently implements exact READY rendering, deterministic player movement and pellet accounting, the recovered four-ghost update, global scatter/chase scheduling, collision resolution, life reset, and the original 32-bit random generator. A target-local Win32 presenter adds keyboard input, integer-scaled CGA output, and the recovered 20 Hz gameplay cadence.

```powershell
cmake -S projects/pakupaku/reimplementation -B projects/pakupaku/.work/build
cmake --build projects/pakupaku/.work/build --config Release
ctest --test-dir projects/pakupaku/.work/build -C Release --output-on-failure
```

Run the interactive Windows build:

```powershell
projects/pakupaku/.work/build/Release/pakupaku_play.exe `
  --data projects/pakupaku/.work/specimen/paku-1.6 `
  --scale 6
```

Steer with the arrow keys or WASD. Exit with Escape or Q.

The reconstructed READY frame, the complete frame after 22 left updates, and
the post-death READY frame after 274 updates are byte-identical to their
state-gated original captures. The preceding death animation, game-over
presentation, level progression, audio, and persistence remain incomplete.

See `checkpoints/03-first-matching-running-frame.md`,
`checkpoints/04-first-life-loss-reset.md`, `licensing.md`,
`adapter-assessment.md`, and `reimplementation/README.md`.
