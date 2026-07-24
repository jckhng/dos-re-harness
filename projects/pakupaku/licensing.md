# Paku Paku licensing assessment

Status: conservative hold on specimen redistribution.

This is a scope assessment, not legal advice.

## Evidence in the supplied release

The bundled `README.HTM` identifies:

- Paku Paku 1.6, dated 9 November 2011;
- Jason M. Knight / Paladin Systems North;
- the game as "Cardware";
- a public-domain statement expressly scoped to "Source Code";
- an accompanying request to credit Jason M. Knight.

The binary-only assessment does not acquire or inspect source code.

## Current boundary

The source-code statement does not clearly place `PAKU.EXE`, the `.DAT` files,
or other runtime content in the public domain. "Cardware" describes the
author's requested payment but is not, by itself, a complete redistribution
grant.

Therefore:

- do not commit or publish the executable, data files, bundled documentation,
  extracted assets, screenshots, audio, framebuffers, memory dumps, save
  states, or Ghidra databases;
- keep the private specimen under `.work/`;
- publish only hashes, independently written schemas, numeric reports, and
  independently written adapter code until a separate rights review supports a
  broader scope;
- treat `SCORES.DAT` as mutable private capture data;
- do not apply the harness MIT license to the specimen.

The manifests, verification script, adapter documentation, and future
independently authored reimplementation code are covered by the repository's
MIT license unless a file states otherwise.

## Reimplementation release constraint

If runtime data redistribution remains unresolved, a released
reimplementation must require a user-provided Paku Paku installation, verify
supported hashes, import data locally, and exclude imported content from
source and binary release archives.

The Paku Paku name and any rights implicated by its Pac-Man-derived gameplay,
visual identity, or audio require separate review before public release.
