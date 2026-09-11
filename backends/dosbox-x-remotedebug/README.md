# DOSBox-X remotedebug backend

The harness expects the `lokkju/dosbox-x-remotedebug` fork at commit
`2917cb31e00a9d0a935060ac9186c1a7885da0fd`, with the patch in this directory
applied. `backend.lock.json` records the source and patch hash. The backend
exposes:

- a GDB Remote Serial Protocol endpoint for halt, continue, registers, and
  memory writes;
- a QMP endpoint for memory reads, keyboard injection, screenshots,
  save-state operations, execution breakpoints, and wave capture;
- a halt-safe `displaydump` of the last completed logical renderer source
  frame, including its width, height, source bit depth, pitch, and generation.
  Unlike `screendump`, this does not resume the guest or wait for another
  vertical refresh.
- an opt-in completed-display history ring. The controller arms it immediately
  before post-resume execution and drains it after the breakpoint, preserving
  fast intervening renderer generations without host polling. Retention is
  bounded to 64 frames and disabled outside an explicitly requested capture;
  QMP uses zlib transfer compression when profitable while retaining exact raw
  renderer bytes and the synchronized 256-entry RGB palette at the controller.
- OPL register logs can inherit the last verified state-input counter, keeping
  sound writes attributable when the DOS driver changes DS before OPL access.
- opt-in, file-backed keyboard transitions at an exact physical-linear guest
  instruction and monotonic 1-, 2-, or 4-byte guest state counter, avoiding a
  remote stop for every emulated tick while retaining an applied-event log.
- an event-only guest-state stop using the same hook and counter without an
  input schedule, for fast forward execution from a saved state to one exact
  logical boundary;
- immediate save and paused load operations that preserve a halted boundary
  without executing an extra guest instruction.

Supply a state-input hook, state address, width, and stop value without an
input script when only an exact terminal boundary is needed. When the harness
saves at that stop, it uses the immediate halted save operation and records
the pre-save registers and state in checkpoint metadata.

State-input schedules may include `# state_unwrap=1`. With that opt-in, event
values address the unwrapped counter: each time the raw guest counter wraps or
resets to a lower value, the backend adds one full counter modulus. This allows
one ordered schedule to cross level loads or other counter epochs without
per-tick remote stops. The default remains raw-counter behavior.

Schedules resumed from a full-machine state after a counter wrap may also set
`# state_epoch_base=<value>`. The first raw state observed is interpreted at
that unwrapped epoch before normal wrap detection continues.

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
uses `./build-debug --enable-remotedebug` inside WSL for initial configuration.
Later `-Build` invocations use incremental `make`; pass `-Reconfigure` with
`-Build` only when configuration must be regenerated.

The current proven build runs inside WSL2. This is an execution adapter, not a
requirement that projects, Ghidra databases, reimplementations, or captures
live inside WSL.
