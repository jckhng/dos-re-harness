# Reuse audit: capture tooling and harness onboarding

One bounded audit of target tooling against the existing harness. The aim is
less repeated infrastructure work for the next target, without importing game
behavior or treating experimental timing results as qualified backend features.

## Decisions

| Candidate | Decision | Reason |
|---|---|---|
| GDT descriptor decoding and checked segment ranges | Promote to `x86_address.py` | Independent of loader, game addresses and resource formats; synthetic boundary tests are sufficient for the arithmetic contract. |
| DOSBox-X breakpoint packing and cold real-mode aliases | Share checked helpers and add RSP methods | Large protected-mode offsets can spill into the selector when hand-packed. The existing capture parser already checks 16-bit components; adapters now have the same lightweight API. |
| Relocation signatures, active selectors and loader-owned GDTR discovery | Keep target-local | These establish a specific executable's address model. They are not a generic protected-mode discovery algorithm. |
| Owned emulator process and clean mount wrapper | Defer extraction | The harness already has connection ownership and launch paths. The target wrapper assumes a particular mount, executable identity and WSL process contract; another abstraction needs a second migration and profiling. |
| Command receipts, input hashes and evidence ledgers | Reuse existing workbench | `execution.run_command`, run/probe plans and evidence status already provide these. Target wrappers should migrate incrementally rather than duplicate the receipt format. |
| CPU/VGA fixture runner | Keep target-local | It models selected VGA operations and skips declared sound callees. Promoting it as a general 32-bit execution engine would overstate its supported devices and calling conventions. |
| PIC/VGA/CPU timing instrumentation | Defer backend promotion | The private backend variants expose useful observations, but fresh captures show scheduling distinctions that need a controlled qualification and a reviewed backend patch/lock update. Instruction counts are not elapsed cycles. |
| Carried mixed-audio and save-state tooling | Defer | Sequencer and cross-platform PCM matches do not establish DOS mixed-waveform parity. Missing mixer history, filter phase and FM implementation differences remain unresolved. |
| Host separation and cross-platform native checks | Document the pattern | Valuable project architecture, but concrete implementations depend on target interfaces. They are not Python harness components. |
| Asset codecs, menus, rendering and application behavior | Keep in the target | These are target formats and behavior, not capture infrastructure. |

## Delivered

- Checked descriptor decoding and nonwrapping memory ranges, with explicit
  rejection of unsupported segment types. No automatic loader discovery or
  paging translation is implied.
- Checked segmented RSP insertion/removal and a below-1-MiB real-mode alias helper.
  Existing wire methods and `remote_capture.pack_segment_offset` remain available.
  See [the address contract](protected-mode-addressing.md).
- A README organized around capabilities, setup, a first milestone and an agent
  prompt, with detailed references deferred to links. A separate
  [getting-started guide](getting-started.md) explains the first capture.
- An explicit DOSBox-X policy in the README, repository `AGENTS.md` and skill.
  Automated capture requires the pinned patched backend; missing dependencies
  must not trigger a silent fallback to classic DOSBox or stock DOSBox-X.

No game project or sealed checkpoint was modified in this audit. No original
bytes, extracted assets, captured descriptors or generated backend binaries are
included in the public changes.

## Validation

Nine new tests first failed because the shared API did not exist, then passed.
They cover descriptor bases, granularity, RPL, 16/32-bit metadata, unsupported
types, truncated tables, segment overruns, linear wrap, cold aliases and rejected
breakpoint offsets without network traffic. Existing packing imports and packet
deduplication remain compatible.

| Environment | Tests run | Result |
|---|---:|---|
| Windows Python 3.11, Unicorn 2.1.4 | 361 | All pass |
| Windows Python 3.8.20, core | 361 | Pass; 29 optional CPU skips |
| Linux Python 3.13.12, core | 361 | Pass; 29 optional CPU skips and one hardlink-permission skip |

The first sandboxed Windows runs could not connect to their local protocol-test
socket. Reruns with local socket access passed; no timeout or protocol test was
weakened. The documented Paku Paku `doctor` and capture dry-run commands execute.

A private comparison checks four captured descriptor records and 4,117 address/
alias cases against the existing target resolver. This is retained-data and
arithmetic qualification, not fresh DOSBox-X execution. No new hardware timing,
gameplay or waveform claim is made. Logs and the comparison are retained under
`.work/improvements/reuse-20261106/`.

## Next reusable boundary

Migrate one target capture to the shared addressing API while retaining its
original entry/stop, fields and artifact hashes. Qualify a high-offset physical
breakpoint with a generated protected-mode specimen before extending the generic
execution controller. Treat backend timing metadata and complete mixer-state
capture as separate proposals with their own pinned-source and regression gates.
