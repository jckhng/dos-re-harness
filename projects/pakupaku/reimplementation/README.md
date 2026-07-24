# Paku Paku compatibility reimplementation

This is an independently written, binary-only compatibility core. It does not
contain Paku Paku executable code, data, screenshots, memory dumps, or extracted
assets.

The current checkpoint implements:

- strict SHA-256 verification of supported Paku Paku 1.6 data files;
- `MAP.DAT` run-length decoding to 28 by 31 cells;
- the 160 by 100 CGA text-semigraphics framebuffer;
- aligned map-tile and sprite mask blitters;
- the variable-width transparent font renderer;
- the complete initial READY scene and HUD;
- deterministic player input buffering, corridor collision, corner boost,
  tunnel wrap, pellet consumption, score, and extra-life accounting;
- the four-ghost update, pen release counters, scatter/chase/frightened/eaten
  branches, global mode timing, and the recovered 32-bit random generator;
- normal and frightened collision branches, ghost-score doubling, life reset,
  and the post-death READY presentation;
- a Windows interactive presenter with crisp integer CGA scaling, buffered
  arrow/WASD input, and the recovered 20 Hz gameplay cadence.

The READY scene is byte-identical to a naturally reached original capture. The
complete frame after 22 combined player/ghost updates and the post-death READY
frame after 274 updates are also byte-identical to state-gated original
captures. The death-animation sequence before reset, game-over presentation,
level progression, score persistence, and audio remain incomplete.

## Build

The runtime requires legally obtained Paku Paku 1.6 data files. The files remain
outside the build and source tree.

```powershell
cmake -S projects/pakupaku/reimplementation `
  -B projects/pakupaku/.work/build
cmake --build projects/pakupaku/.work/build --config Release
ctest --test-dir projects/pakupaku/.work/build -C Release --output-on-failure
```

## Play on Windows

The interactive target is built only on Windows. It reads legally obtained,
hash-verified Paku Paku 1.6 data files at runtime:

```powershell
projects/pakupaku/.work/build/Release/pakupaku_play.exe `
  --data projects/pakupaku/.work/specimen/paku-1.6 `
  --scale 6
```

Use the arrow keys or WASD to steer. Press Escape or Q to exit. `--scale`
accepts values from 1 through 12. The initial and post-life-loss READY holds
last two seconds; gameplay advances at 20 updates per second.

This checkpoint is playable through life loss, but it skips the original
death animation. It has no sound, level transition, persistent scores, or
complete game-over presentation yet.

Render the initial READY scene:

```powershell
projects/pakupaku/.work/build/Release/pakupaku.exe `
  --data projects/pakupaku/.work/specimen/paku-1.6 `
  --scene ready `
  --raw projects/pakupaku/.work/ready.bin `
  --ppm projects/pakupaku/.work/ready.ppm
```

Run 22 deterministic combined game updates:

```powershell
projects/pakupaku/.work/build/Release/pakupaku.exe `
  --data projects/pakupaku/.work/specimen/paku-1.6 `
  --scene game --steps 22 --direction left `
  --raw projects/pakupaku/.work/game.bin `
  --ppm projects/pakupaku/.work/game.ppm `
  --state-json projects/pakupaku/.work/game.json
```

Render the first natural life-loss reset checkpoint:

```powershell
projects/pakupaku/.work/build/Release/pakupaku.exe `
  --data projects/pakupaku/.work/specimen/paku-1.6 `
  --scene game --steps 274 --direction left `
  --raw projects/pakupaku/.work/life-loss.bin `
  --ppm projects/pakupaku/.work/life-loss.ppm `
  --state-json projects/pakupaku/.work/life-loss.json
```

To enable the asset-backed checkpoint in `pakupaku_game_tests`, point the test
at a verified private installation:

```powershell
$env:PAKUPAKU_DATA_DIR = (Resolve-Path `
  projects/pakupaku/.work/specimen/paku-1.6).Path
projects/pakupaku/.work/build/Release/pakupaku_game_tests.exe
```

The core is C++17 with CMake and has no emulator, Ghidra, WSL, or harness
runtime dependency.
