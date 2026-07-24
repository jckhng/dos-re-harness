# DOSBox-X remotedebug backend

The harness expects the `lokkju/dosbox-x-remotedebug` fork at commit
`2917cb31e00a9d0a935060ac9186c1a7885da0fd`, with the patch in this directory
applied. `backend.lock.json` records the source and patch hash. The backend
exposes:

- a GDB Remote Serial Protocol endpoint for halt, continue, registers, and
  memory writes;
- a QMP endpoint for memory reads, keyboard injection, screenshots,
  save-state operations, execution breakpoints, and wave capture.

The patch and DOSBox-X-derived backend are GPL-2.0-only. See `COPYING`.
Distributing a patched executable requires satisfying the corresponding-source
and notice requirements of that license. The harness does not require DOSBox-X
code to be linked into the Python package, and this repository does not
distribute a backend executable.

Prepare a pinned checkout and apply the patch from Windows:

```powershell
.\scripts\prepare-wsl-backend.ps1
```

Add `-Build` after installing the upstream Linux build dependencies. The build
uses `./build-debug --enable-remotedebug` inside WSL.

The current proven build runs inside WSL2. This is an execution adapter, not a
requirement that projects, Ghidra databases, reimplementations, or captures
live inside WSL.
