# Example Projects Roadmap

Kingdom of Kroz and Paku Paku should validate that the harness generalizes
across different DOS display, input, timing, and audio models. They are
separate example projects with separate source and license records, not code
copied into the harness core.

## Release Rules

- Record upstream source, version, license text, and SHA-256 specimen hashes.
- Do not bundle retail binaries or data unless their license explicitly permits
  redistribution.
- Keep target addresses, symbols, scenarios, and adapters under
  `projects/<id>/`.
- Keep each portable reimplementation in its own repository or top-level
  example directory.
- Require Windows and Linux builds for each reimplementation.
- Require deterministic state and framebuffer comparisons for the published
  scenarios.

## Kingdom of Kroz

Primary purpose: exercise BIOS text mode, keyboard timing, deterministic world
generation, entity scheduling, and PC speaker behavior.

Candidate upstream: the classic Apogee source release announced by 3D Realms:
https://legacy.3drealms.com/news/the_classic_games/

Milestones:

1. Verify the exact source archive and license before importing anything.
2. Create specimen and symbol manifests.
3. Capture title, new-game entry, one deterministic room, death, and level
   transition scenarios.
4. Add text-cell and attribute comparison to the core.
5. Reimplement one vertical slice with portable SDL/CMake output.
6. Extend to a complete implementation only after zero-diff input and state
   traces are repeatable on Windows and Linux.

## Paku Paku

Primary purpose: exercise CGA graphics, palette behavior, raster timing,
keyboard input, sound, and compact game-state tracing.

Candidate upstream: the Paku Paku source release listed as public domain by DOS
Games Archive:
https://www.dosgamesarchive.com/download/paku-paku/

Milestones:

1. Verify the downloaded archive, embedded notices, and redistribution terms.
2. Create specimen, memory-layout, screen-signature, and scenario manifests.
3. Capture title, attract mode, first movement, pellet consumption, collision,
   death, and level-clear scenarios.
4. Add CGA memory-layout decoding and palette-aware comparison.
5. Reimplement the same scenarios with portable SDL/CMake output.
6. Publish known-good original/reimplementation evidence without distributing
   files whose license does not permit it.

## Harness Exit Criteria

The examples are ready to ship with the harness when:

- a clean checkout can validate both project manifests on Windows and Linux;
- the documented backend build is reproducible;
- input movies replay against explicit emulated ticks rather than wall time;
- text, indexed-framebuffer, state, and trace comparison commands are
  target-independent;
- evidence manifests identify every executable, data file, tool, configuration,
  and capture artifact by hash;
- each reimplementation builds without WSL or Windows-only APIs.
