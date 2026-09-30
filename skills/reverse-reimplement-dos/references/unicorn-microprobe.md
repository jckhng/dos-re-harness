# Optional Unicorn Micro-Probes

Use this path only for a bounded 16-bit routine whose inputs and return ABI
are known. Install the optional extra with `python -m pip install -e ".[unicorn]"`.
The portable game must not depend on Unicorn.

1. Hash the exact original executable, RAM image, and register snapshot.
   Verify expected instruction bytes and segment bases at the entry.
2. Build each fixture from a fresh copy of the same private RAM image. Record
   every synthetic write, initial register, entry and return CS:IP, and stack
   convention. The runner inserts a synthetic near or far return address.
3. Call `run_callback(memory, registers, entry=(cs, ip),
   return_address=(cs, ip), return_kind="far", max_instructions=N)`. Start
   Unicorn at the **linear** address `CS*16+IP`; the runner handles this. Set
   a finite instruction cap and keep the default finite wall-time cap.
4. Reject a fixture if execution touches an interrupt, port I/O, unmapped
   memory, or fails to reach the return. Do not stub unknown DOS or device
   behavior merely to make a probe pass.
5. Compare the resulting memory slice and state fields with a **separate**
   DOSBox original-binary call made from the same snapshot and fixture. Report
   hashes, first differing byte, executed-instruction count, and exclusions.

Batch independent fixtures by restoring the snapshot for each call. Reuse a
pinned DOSBox reference only while the executable, snapshot, fixture and
capture provenance remain identical. Report unsupported cases separately;
never count a prefix stopped at a DOS interrupt as a matching callback.

Unicorn runs the CPU, not DOS, BIOS, video, sound, timers, or interrupts. RAM
restoration does not restore device state. Even a byte-identical callback
result is `controlled_imported_snapshot_non_promotable`: it can narrow a
code-level mismatch, not establish natural campaign or pixel/audio fidelity.
Keep proprietary snapshots and output in ignored private work directories.
