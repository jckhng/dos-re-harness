# Configuration and publication

Portable plans describe a target experiment. Explicit private host profiles
select installed tools and machine paths. Generated receipts, originals,
captures and local profiles belong under ignored `.work/`.

## Portable jobs and private profiles

The existing `run-plan` interface accepts named jobs in version 2. Version 1
retains its existing literal argument/environment semantics unless a profile is
explicitly selected. Neither version runs a shell or automatically finds profiles.

```powershell
New-Item -ItemType Directory -Force .work | Out-Null
Copy-Item examples/host.example.json .work/host.json
python -B -m dos_re_harness.cli run-plan examples/jobs.example.json --job smoke --host-profile .work/host.json --out-dir .work/smoke-01 --dry-run
python -B -m dos_re_harness.cli run-plan examples/jobs.example.json --job smoke --host-profile .work/host.json --out-dir .work/smoke-01
```

Run from the repository root after installation, or set `PYTHONPATH=src` in the
calling environment. Edit the private profile when a tool needs an absolute path
or an argument prefix, such as a compiler launched through its environment wrapper.
The example works with Python on PATH. Outputs must be fresh.

Profile v1 fields are `tools` (alias to argv prefix), `values` (string variables),
`environment` (string overrides) and `unset_environment` (variable names).
Profile values may use `${profile_dir}`; tool prefixes/environment may also use
those values. Relative executable paths with a separator resolve against the
profile directory; bare names use PATH. Profile contents are bound into receipts.

Run-plan v2 contains `jobs` and optional `input_groups`. Each named group is a
list of `{path,sha256}` bindings. A job selects groups through `input_groups` and
may add its own `inputs`. Equal bindings merge; conflicting hashes reject.
Unselected groups are shape-validated without hashing their files. This avoids
invalidating an unrelated experiment. Completeness is still a caller declaration.

Jobs accept the v1 command/cwd/environment/inputs/timeout/dependency fields plus
`unset_environment`, `input_groups`, `expected_exit_code`, `expected_stdout` and
`expected_stderr`. The latter two are lists of required literal substrings.
The exit code defaults to zero. Expansion uses `${plan_dir}` and explicit profile
values; unknown variables reject. `$${name}` emits literal `${name}`. Binding paths
remain relative to the plan and are not interpolated.

Environment precedence is inherited environment, profile, then job. A removal
deletes an earlier assignment, including inherited overrides; setting a variable
in a later layer restores it. Setting and unsetting the same name within one
layer rejects. Windows names are case-insensitive. The parent process is unchanged.

An expected nonzero exit can pass a negative-control job. The raw receipt still
records `failed`, its actual exit code and `cache_eligible=false`.
`job-result.json` separately records whether expectations matched. Timeouts,
launch/preflight errors and changed inputs cannot pass expectations. A matching
job is execution evidence, never game-fidelity qualification. No cache hit or retry
is introduced. See [the workbench](workbench.md) for receipt and CPU contracts.

## Publication boundaries

```text
dos-re audit-public-tree --staged
dos-re audit-public-tree --paths-from .work/public-files.txt
dos-re audit-public-tree path/to/export
```

`--staged` checks the exact Git index blobs, including force-added private/generated
paths. It does not inspect later working-copy edits or stage anything. Unmerged,
symlink and submodule entries require review. Use the repository root.

`--paths-from` checks an explicit UTF-8 newline list of repository-relative files;
it does not enumerate neighboring game projects. This supports reviewing new
files before staging. Escaping the selected root and symlinks reject. A directory
audit remains useful for a prepared export, pruning ignored trees before walking.

The gate checks file types/magic, size, local configuration names, full text up to
the size limit, user-home/workspace paths (including escaped and WSL spellings),
and absolute host paths in JSON path fields. Oversize files reject. Portable
examples are allowed; actual `.env`, `*.local.json/toml/yaml/yml`, `host.json` and
`CMakeUserPresets.json` are private. This conservative gate cannot detect every
secret or every hardcoded host dependency; review the publication selection too.
Ignored originals and captures must never be force-added.

## Data-free validation

`python -B scripts/run_tests.py` is the shared Windows/Linux runner. PowerShell
entry points delegate to it. `--temp-root`, `--pattern` and `--dependency-path`
select scratch storage, a cohort and an existing optional dependency directory.
Scratch create/rename/delete is checked before tests. Environment and cwd changes
apply only to the child, with bytecode disabled. No runtime dependency is installed.

The CI workflow runs the core on Windows and Ubuntu 24.04, checks the declared
Python 3.8 minimum on Windows, and runs optional pinned Unicorn CPU tests on both
systems. It needs no game data, DOSBox, Ghidra, native game build or graphics SDK.
Capture/backend and game release validation remain separate target-owned work.
