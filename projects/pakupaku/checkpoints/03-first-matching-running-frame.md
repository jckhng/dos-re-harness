# Checkpoint 03: first matching running frame

## Objective

Match a naturally reached running state after deterministic player and ghost
updates, beyond the already matched READY frame.

## Evidence added

- Two private state-gated original captures reached player X 18, score 70, and
  237 remaining pellets after a held-left start.
- The captures agree on current player state, all four current ghost records,
  release counters, modes, and RNG state `0x45efab28`.
- Static analysis recovered the update scheduler, ghost routine, and RNG
  recurrence without consulting Paku Paku source code.
- The first original capture and the reimplementation both produce raw-frame
  SHA-256 `d786086a2f871adf11e9f000e5538bc9d0ed38f8c340b605422b8a9f2b0438a3`.

The original binary, captures, memory dumps, and analysis database remain under
ignored `.work/` paths.

## Reproduction

Capture the original state into a private directory:

```powershell
pwsh -NoProfile -File scripts/dos-re.ps1 capture `
  projects/pakupaku/project.json first-movement `
  --out-dir projects/pakupaku/.work/captures/first-movement
```

Build and render the corresponding reimplementation state:

```powershell
cmake -S projects/pakupaku/reimplementation `
  -B projects/pakupaku/.work/build
cmake --build projects/pakupaku/.work/build --config Release
projects/pakupaku/.work/build/Release/pakupaku.exe `
  --data projects/pakupaku/.work/specimen/paku-1.6 `
  --scene game --steps 22 --direction left `
  --raw projects/pakupaku/.work/checkpoint-03.bin `
  --ppm projects/pakupaku/.work/checkpoint-03.ppm `
  --state-json projects/pakupaku/.work/checkpoint-03.json
```

Run the asset-backed state regression:

```powershell
$env:PAKUPAKU_DATA_DIR = (Resolve-Path `
  projects/pakupaku/.work/specimen/paku-1.6).Path
projects/pakupaku/.work/build/Release/pakupaku_game_tests.exe
```

## First remaining divergence

Collision/death handling after player contact is not implemented. Global ghost
mode timing, level progression, score persistence, audio, and an interactive
presenter are also incomplete.

## Harness limitations

The backend screenshot request times out on this host even though DOSBox-X
writes a private PNG. Raw `B800:0000` capture is authoritative. A sampled
screen can differ in previous-position cleanup while decoded current state is
identical, so state gating precedes raw-frame comparison.

## Rights boundary

Do not publish the original executable, data, bundled documentation, captures,
screenshots, framebuffers, memory dumps, save states, or Ghidra database. The
reimplementation requires a user-provided installation and verifies supported
data hashes locally.
