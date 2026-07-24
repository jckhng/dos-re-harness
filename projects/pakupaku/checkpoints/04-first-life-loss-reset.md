# Checkpoint 04: first life-loss reset

## Objective

Match the first naturally reached normal-ghost collision through life decrement,
actor reset, global ghost-mode state, and the post-death READY frame.

## Evidence added

- A manifest-backed original capture reaches the first life loss after 274
  combined player/ghost updates while holding left from READY.
- Static analysis recovered collision routine `1000:2b4a`, actor reset helper
  `1000:2862`, ghost-mode scheduler `1000:29bc`, and score addition helper
  `1000:1006` without consulting Paku Paku source code.
- The original and reimplementation agree on RNG state `0x4885f938`, lives 2,
  score 70, 237 remaining pellets, global mode 1, mode phase 2, mode timer 240,
  and every reset actor record.
- Both post-death READY framebuffers have SHA-256
  `d0038f3fa4fe07c9d7053c54700a054e3f01e02bb298f5ff1576efc349cb7a9e`.

The original binary, capture, memory dump, framebuffer, screenshot, and Ghidra
database remain under ignored `.work/` paths.

## Reproduction

Capture the original state and write its private evidence manifest:

```powershell
pwsh -NoProfile -File scripts/dos-re.ps1 capture `
  projects/pakupaku/project.json first-life-loss `
  --out-dir projects/pakupaku/.work/captures/first-life-loss
```

Build and render the corresponding reimplementation state:

```powershell
cmake -S projects/pakupaku/reimplementation `
  -B projects/pakupaku/.work/build
cmake --build projects/pakupaku/.work/build --config Release
projects/pakupaku/.work/build/Release/pakupaku.exe `
  --data projects/pakupaku/.work/specimen/paku-1.6 `
  --scene game --steps 274 --direction left `
  --raw projects/pakupaku/.work/life-loss.bin `
  --ppm projects/pakupaku/.work/life-loss.ppm `
  --state-json projects/pakupaku/.work/life-loss.json
pwsh -NoProfile -File scripts/dos-re.ps1 diff-frame `
  --expected projects/pakupaku/.work/captures/first-life-loss/remote_runtime_vga.bin `
  --actual projects/pakupaku/.work/life-loss.bin `
  --width 160 --height 100
```

Run the asset-backed state regression:

```powershell
$env:PAKUPAKU_DATA_DIR = (Resolve-Path `
  projects/pakupaku/.work/specimen/paku-1.6).Path
projects/pakupaku/.work/build/Release/pakupaku_game_tests.exe
```

## First remaining divergence

The reimplementation transitions synchronously to the matched reset state. The
original first presents a 181-tick death animation and associated audio. That
ordered temporal sequence is not implemented. Game-over presentation after the
last life is also incomplete.

## Harness limitations

The backend QMP screenshot request times out on this host even though DOSBox-X
writes a private PNG. Raw `B800:0000` capture is authoritative. The state gate
targets completed actor reset; it does not validate intermediate death frames.

## Rights boundary

Do not publish the original executable, data, bundled documentation, captures,
screenshots, framebuffers, memory dumps, save states, or Ghidra database. The
reimplementation requires a user-provided installation and verifies supported
data hashes locally.
