# Third-Party Notices

The root MIT license applies to original `dos-re-harness` Python, PowerShell,
Java, documentation, manifests, and tests except where a file or directory
states otherwise.

## DOSBox-X Remotedebug Backend

`backends/dosbox-x-remotedebug/dosbox-x-remotedebug.patch` modifies the
DOSBox-X remotedebug fork and is distributed under `GPL-2.0-only`, consistent
with the upstream project.

- Source: https://github.com/lokkju/dosbox-x-remotedebug.git
- Pinned commit: `2917cb31e00a9d0a935060ac9186c1a7885da0fd`
- License text: `backends/dosbox-x-remotedebug/COPYING`
- Reproduction metadata:
  `backends/dosbox-x-remotedebug/backend.lock.json`

The repository does not distribute a DOSBox-X executable. Anyone distributing
a patched executable must satisfy the GPL requirements for corresponding
source and notices.

## Target Software

Target project names, hashes, schemas, addresses, and automation manifests do
not grant a license to the target software. Proprietary binaries, data files,
extracted assets, captures, and Ghidra databases are not part of this
repository.
