# Progress accounting

Report recovered source ranges, verification evidence and natural playability
separately. The reporter reads a versioned inventory and checks pinned file
identities. It does not run the original, replay the port or change acceptance
criteria. There is no combined fidelity or task-completion percentage.

```powershell
$env:PYTHONPATH='src'
python -B -m dos_re_harness.progress INVENTORY.json
python -B -m dos_re_harness.progress INVENTORY.json --format markdown --out REPORT.md
```

JSON is the default. Output is deterministic for the same inventory and files;
it contains no timestamp. Exit 0 means a valid report was produced, including
reports with failures, stale evidence or incomplete coverage. Exit 2 means the
inventory or file operation was invalid. Output cannot replace the inventory or
any bound input, including resolved aliases and existing hardlinks.

## Inventory v1

Required top-level fields:

| Field | Meaning |
| --- | --- |
| `format_version` | Integer 1 |
| `id` | Existing target/inventory identity |
| `specimen` | Exact original file binding |
| `inventory_complete` | Explicit declaration of complete scope; structural gaps still force the report incomplete |
| `scope_description` | Address basis, included program scope and omitted modules |
| `spaces` | Nonaliasing file-offset address spaces |
| `regions` | Code, unknown and excluded byte ranges |
| `units` | Identified functions or source ranges and reconstruction status |
| `verification` | Named scenario/observable records |
| `milestones` | Natural playability requirements |

Optional `notes` records limits and provenance. A file binding is
`{"path":"relative/or/absolute/file","sha256":"64 hexadecimal characters"}`,
optionally with `bytes`. Relative paths resolve against the inventory directory.
Use the existing specimen, map, scenario and manifest identities. Bindings check
declared files only; they do not recursively validate manifest contents. State
which dependencies were inherited or omitted in each record's notes.

Spaces contain `id`, `size`, `artifact` binding and `description`. Their scope is
the whole pinned file `[0,size)`. Put MZ headers, relocation metadata and known
data in explicit excluded regions when the chosen recovery denominator warrants
it. The reporter rejects duplicate file/hash spaces, preventing a relocated or
aliased view of the same file from earning a second byte count. Runtime modules
with their own files require separate, documented specimen lineage.

Regions contain `id`, `space`, integer `start`/`end`, `kind` and `reason`.
Ranges are half-open, nonempty and within their space. Kinds are `code`,
`unknown` and `excluded`; unknown/excluded need a reason. Regions cannot overlap.
Unlisted gaps become unknown regions automatically. IDs beginning `gap:` are
reserved for those derived gaps. Never infer a function end from the next symbol.

Units contain these fields:

| Field | Meaning |
| --- | --- |
| `id`, `kind`, `space` | Original function/range identity; kind is `function` or `range` |
| `ranges` | List of `{start,end}` source extents; empty for mapped symbols without known extents |
| `extent_complete` | Whether these extents fully describe the declared unit |
| `recovery` | `unrecovered`, `partial`, `reconstructed`, `stub` or `original-fallback` |
| `integrated` | Independent implementation integration declaration |
| `implementation`, `evidence` | Lists of pinned implementation and source/contract evidence files |
| `notes` | Supported behavior/domain and unresolved limits |

Every extent must fit a code region. Unit extents cannot overlap within or
between units, including shared tails and nested functions. Give shared code
one owner or partition its ranges explicitly. `reconstructed` requires a
complete nonempty extent and both implementation and evidence bindings.
Recovery credit additionally requires current specimen, source, implementation
and evidence bindings. Partial work, stubs and original fallbacks earn zero
complete reconstruction bytes, even when they are integrated.

`included_bytes = scope_bytes - excluded_bytes`. Unknown bytes stay in this
denominator. The report also exposes known code bytes, unknown bytes and code
bytes not assigned to a unit. Its scoped byte ratio is accounting coverage;
incomplete function discovery and unclassified data limit its interpretation.
Function counts include only declared function units, with complete extents and
current reconstruction shown separately. Range units and integration declarations
have their own counts. These are declared recovery facts, not automatic semantic
equivalence proofs. A structurally complete inventory still needs source review.

## Verification and natural playability

Each verification row contains `id`, `scenario`, `observable`, `execution`,
`reference`, `result`, `evidence`, `inputs` and `notes`.

- Execution: `natural`, `controlled` or `component`.
- Reference: `original` or `portable`.
- Recorded result: `pass`, `fail`, `not_run` or `unsupported`.
- Evidence/inputs: lists of pinned files; both lists must be nonempty for current
  evidence. Missing files/lists report missing; changed hashes or lengths report
  stale. Missing takes precedence over stale.

The recorded result survives freshness changes. A current failure remains
failing; a stale recorded pass remains stale. `current` means the declared
dependencies match their recorded identities. It does not mean the tests were
executed again or all transitive dependencies are covered. Bind current source,
executable, specimen/resources, movies, comparison outputs and qualifying original
artifacts where the claim depends on them. Existing reviewed provenance and
immutable acceptance caches remain authoritative within their recorded scope.
Do not refresh hashes to turn obsolete evidence into a current pass.

Milestones contain `id`, `description`, declared `status` (`not_implemented`,
`partial` or `implemented`) and `checks` referencing verification IDs. A milestone
is satisfied only when implemented with nonempty, current passing natural checks.
Controlled armor routes, direct starts and component matches cannot satisfy that
gate. Write a bounded description when the milestone covers semantic playability
only; full original temporal/audio fidelity needs its own verification records.

## Initial Stellar 7 inventory

The initial private inventory is at
`projects/Stellar7/.work/analysis/checkpoint288-progress/inventory.json`:

```powershell
$env:PYTHONPATH='src'
python -B -m dos_re_harness.progress projects/Stellar7/.work/analysis/checkpoint288-progress/inventory.json --out projects/Stellar7/.work/analysis/checkpoint288-progress/report.json
```

It uses the pinned unpacked image, existing symbol identities and checkpoint287
records. Its code/function inventory is incomplete: twenty mapped annotations
have no extents, and one reviewed 21-byte source interval is accounted for. The
135,325-byte load image also contains unclassified code/data/library bytes.
This first backfill cannot measure the project's total recovered code or tasks
remaining. Broader existing implementation is not silently credited by filename.

Recorded verification includes current bounded state/pixel checks, audio failures,
unrun acceptance cases and an intentionally stale prior route record. Natural
Level1 retry has a bounded semantic milestone; current natural Level1 completion
and the wider campaign remain open. All original evidence and runtime acceptance
criteria remain intact. The private import script refuses to replace the frozen
inventory; update individual records only after reviewing their new evidence.

Synthetic contract tests:

```powershell
$env:PYTHONPATH='src'
python -B -m unittest discover -s tests -p test_progress.py
```
