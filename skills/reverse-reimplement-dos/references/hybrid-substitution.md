# Hybrid Substitution as a Verification Ladder

## Purpose

Hybrid substitution replaces one recovered subsystem inside the original DOS
program and checks whether the surrounding original runtime observes any
behavioral change.

This is stronger than offline output comparison at that subsystem boundary:
the replacement must satisfy the real calling convention, segment model,
integer behavior, global-state assumptions, caller ordering, and runtime
schedule. It remains weaker than a standalone portable reimplementation
because the unreplaced original program can supply hidden behavior or mask an
incomplete contract.

Use hybrid substitution to extract and close contracts. Do not make a patched
original executable the product architecture.

## Three-Layer Evidence

Require complementary evidence:

1. Contract tests exercise recovered arithmetic, branches, formats, and edge
   cases outside the original.
2. Hybrid substitution proves that a drop-in replacement works under original
   callers and runtime state.
3. Standalone differential tests prove that the portable program remains
   faithful after the original scaffolding is removed.

Passing one layer does not imply the others.

## Candidate Selection

Prefer a routine that:

- has a recovered and instruction-checked ABI;
- accepts explicit inputs and produces explicit outputs;
- is deterministic and hardware-independent;
- has bounded global-state and allocation dependencies;
- is exercised frequently by a short reproducible route;
- fits in place or has a verified trampoline destination;
- already has a pristine state, trace, or presentation regression.

Reject or defer a candidate when:

- initialization or overlay loading changes its address unpredictably;
- interrupt, device, allocator, or self-modifying-code behavior dominates;
- callers or branches remain unidentified;
- replacement requires a broad memory carve-out with no lifetime proof;
- the available route does not exercise the important modes;
- comparison can only observe a terminal screenshot.

## Required Record

For every substitution record:

- pristine packed specimen hash;
- private unpacked/static-analysis derivative hash, if used;
- target routine static and runtime addresses;
- exact original range length and hash;
- recovered calling convention, argument layout, segment assumptions, return
  convention, and preserved registers;
- replacement source, build command, tool version, bytes, length, and hash;
- exact patch, poke, in-place overwrite, or trampoline bytes;
- backend lock and runtime configuration;
- source checkpoint or natural startup route;
- input schedule and next transition after the source checkpoint;
- active-invocation evidence;
- pristine and substituted capture commands;
- explicit volatile or ignored ranges with a semantic justification;
- whether initialization was bypassed;
- whether a persistent patched executable was boot-tested.

Keep executable derivatives, replacement binaries, captures, save states,
memory dumps, and patch manifests under the target's private work directory.
Target-specific assembly, addresses, adapters, and analyzers belong under the
target tree.

## Procedure

1. Pin the pristine regression before writing replacement code.
2. Recover the routine through decompilation, full disassembly, callers,
   callees, and runtime observations.
3. Determine the exact byte range and verify it against the private executable
   image.
4. Write a structurally independent implementation from the recovered
   contract. Do not copy the original instruction stream and call that an
   independent reimplementation.
5. Reject an oversize in-place replacement. Use a trampoline only after
   proving the destination memory is owned, executable, stable, and unused for
   the entire test interval.
6. Build through a manifest-producing tool that refuses unexpected specimen
   or routine hashes.
7. Apply the replacement only after a known-safe load or checkpoint boundary.
8. Prove execution by stopping at the replacement entry or by using a
   behavior-neutral invocation counter whose storage lifetime is justified.
9. Resume pristine and substituted runs from the same full state or from
   separately proven natural-equivalent boundaries with the same pending
   input schedule.
10. Compare semantic state first, then indexed framebuffer and palette,
    temporal frames, audio events, and screenshots as applicable.
11. Explain every excluded byte range. Stack residue, allocator scratch, and
    timing fields are not automatically safe to ignore.
12. Boot-test a persistent derivative when static patching is part of the
    claimed workflow. A debugger-time poke alone does not prove the patched
    executable loads.
13. Move the closed contract into the portable implementation and retain
    standalone differential acceptance tests.

## Interpretation

A passing hybrid result proves only the exercised contract under the observed
surrounding runtime. It does not prove:

- unexercised branches or callers;
- host portability;
- absence of hidden global dependencies outside the observed route;
- equivalence of separately written portable code;
- whole-program fidelity after original subsystems are removed.

A Ship-of-Theseus sequence can be useful: replace deterministic leaves first,
then composition, scheduling, presentation, and hardware adapters. At every
stage preserve the pristine control and standalone acceptance path. The final
claim must come from the independent portable program, not from the fraction
of original code remaining in a hybrid binary.

## Reuse Boundary

The workflow, manifests, address validation, byte-range verification,
invocation proof, and A/B comparison policy are reusable.

Do not move a target capability into the generic harness core after one use.
Generalize code only after another target demonstrates the same missing
backend operation or comparison primitive. Otherwise document the pattern in
this skill and keep the implementation target-local.
