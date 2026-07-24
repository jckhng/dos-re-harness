# Paku Paku harness-adapter assessment

Status: runnable and validated for title, READY, state, first movement, and a byte-exact first-life-loss reset.

## Binary-only evidence

| Observation | Evidence | Confidence |
| --- | --- | --- |
| Release is Paku Paku 1.6 dated 9 November 2011 | bundled `README.HTM` | high |
| Display is 160 by 100 CGA text semigraphics using character `0xDD` | documentation, raw captures, rendering routines | high |
| `MAP.DAT` is RLE and expands to 28 by 31 cells | exact expansion length and map-loader decompilation | high |
| Map tiles are 3 by 3 masked blits with 24-byte odd/even records | video routine at `13b1:095c`; byte-exact READY reproduction | high |
| Sprites are 5 by 5 masked blits with 60-byte odd/even records | video routine at `13b1:09bf`; byte-exact READY reproduction | high |
| `FONTS.DAT` holds 128 eight-row glyphs plus 128 advance widths | file layout and font routines; byte-exact HUD reproduction | high |
| Runtime directions are 0 up, 1 right, 2 down, 3 left | input and player-update routines | high |
| Score, lives, level, pellets, player, and four ghost records are recovered | static callers plus READY/running state captures | high |
| The ghost scheduler updates all four ghosts once per player update | scheduler and state-gated running captures | high |
| RNG recurrence is `state = state * 0x08088405 + 1` modulo 2^32 | RNG routines and matched state after 88 calls | high |
| Normal collision uses distance less than 2 on both axes, decrements lives, and resets actors | collision/reset routines and first-life-loss capture | high |
| Frightened collision adds the current ghost score, doubles it, and enters pen-return mode | collision and score-add routines | high |
| Level 1 alternates recovered scatter/chase intervals before saturating in chase | scheduler table and natural 274-update reset | high |
| `SCORES.DAT` is mutable | embedded filename and pristine absence | high |

## Adapter

`capture.ps1` verifies the specimen and launches the pinned private backend with:

- `machine=cga`;
- `cputype=auto`;
- `cycles=fixed 3000`;
- `PAKU.EXE /speaker`;
- clean copied mount;
- DS-linear 64 KiB dump;
- raw video at linear `0xb8000`, 160 bytes by 100 rows.

Two title captures established a stable lower-screen signature. Two title-to-game captures produced the same complete READY framebuffer hash. A third state-gated READY capture confirmed the transition naturally.

The backend QMP screenshot request currently times out, but DOSBox-X still writes a private PNG. Raw video capture and classification are unaffected and are the authoritative evidence path.

## Generic-core decision

Two genuinely reusable launcher gaps were fixed in the generic PowerShell adapter:

- project-declared machine, CPU type, cycles, and program arguments;
- project-declared video address and raw geometry.

The WSL invocation was also corrected to `wsl.exe --exec bash -lc`, because positional arguments were otherwise dropped on this host. Contract tests assert that these settings remain generic and contain no Paku-specific defaults.

The generic evidence manifest also records the backend lock, verified patch,
emulator configuration, capture selection, and mutable-file baseline. This is
target-neutral; Paku supplies only declarative values in `project.json`.

CGA text decoding, map calibration, far-pointer state inspection, and reimplementation logic remain project-local. No target-specific logic was added to the generic Python core.

## Confirmed checkpoints

- Original READY raw SHA-256: `cba01bb743e5b1dec829af45a101770872987659c6bb242a6b22cf0c46a5c097`.
- Reimplementation READY frame: zero differing bytes.
- State-gated running capture after 22 left updates: raw SHA-256 `d786086a2f871adf11e9f000e5538bc9d0ed38f8c340b605422b8a9f2b0438a3`.
- Reimplementation after 22 combined updates: the same SHA-256, with RNG state `0x45efab28` and all four decoded ghost records matching.
- State-gated first-life-loss reset after 274 updates: raw SHA-256 `d0038f3fa4fe07c9d7053c54700a054e3f01e02bb298f5ff1576efc349cb7a9e`.
- Reimplementation after 274 updates: the same SHA-256, with RNG state `0x4885f938`, lives 2, score 70, 237 pellets, global mode state, and all reset actors matching.
- First remaining behavioral divergence: the temporal death-animation sequence before the matched reset frame.
