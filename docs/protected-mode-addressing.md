# Protected-mode address helpers

`dos_re_harness.x86_address` provides checked segment arithmetic. Loader discovery,
CPU mode validation and game-specific selectors remain in target adapters.

## Resolve a selector from captured descriptors

```python
from dos_re_harness.x86_address import decode_gdt_segment

# Supply the validated table, clipped to GDTR.limit + 1 bytes.
data = decode_gdt_segment(gdt_bytes, registers["ds"])
linear = data.address(offset=0x12345, size=32)
payload = rsp.read_memory_chunked(linear, 32)
```

The helper decodes present legacy code/data descriptors, byte/page granularity,
base, inclusive limit and default operand width. RPL does not alter the index.
Null, LDT, system, expand-down and long-mode descriptors reject. Range checks
reject empty reads, segment overruns and 32-bit linear wrap.

The adapter must establish CPU mode, locate/validate the actual GDT, check
expected descriptor types and selectors, and handle privileges/paging. A
loader-owned table needs correspondence with active runtime state. Keep entry
signatures and loader offsets in the target, not in this module.

The pinned backend reports EIP as CS.base plus architectural EIP. Resolve the
code descriptor before subtracting its base. Existing real-mode register-write
and near-call helpers are not general protected-mode execution helpers.

## Encode DOSBox-X breakpoints safely

The pinned RSP `Z0`/`z0` API packs a 16-bit segment and 16-bit offset. This is
distinct from a physical-linear memory address:

```python
rsp.insert_segmented_breakpoint(0x28, 0x4321)
rsp.remove_segmented_breakpoint(0x28, 0x4321)
```

Both reject an offset above `0xffff` before sending a packet. Hand-packing
`(selector << 16) | eip` with a larger EIP corrupts the selector. The historical
`insert_breakpoint(linear_address)` retains its low-level wire contract; its
argument name does not make the address linear. The existing
`remote_capture.pack_segment_offset` import remains compatible.

For a known physical location below 1 MiB, an adapter can arm a real-mode alias
**before** loading or entering protected mode:

```python
from dos_re_harness.x86_address import real_mode_breakpoint

# Only while the stopped CPU is confirmed to be in real mode.
encoded = real_mode_breakpoint(physical_address)
rsp.insert_breakpoint(encoded)
```

DOSBox-X resolves the physical location at insertion. In protected mode the same
numbers mean a selector and offset. Verify preservation across the chosen
load/transition and record the stopped PC; remove using the original encoded
identity. This helper does not verify CPU mode or support addresses above 1 MiB.

## Limits

Synthetic tests cover descriptor boundaries, unsupported types and wire-level
breakpoint behavior. These helpers do not alter backend scheduling, IRQ delivery,
save-state formats or gameplay. Successful address resolution and CPU instruction
counts do not establish elapsed time. Use DOSBox-X for system-level checks.
