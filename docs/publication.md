# Public Repository and Checkpoints

Create a new repository from the cleaned `dos-re-harness` directory. This is
preferable to a subtree split while the toolkit has no independent public
history. It prevents unrelated target-project commits and original files from
entering the new repository.

## Preflight

1. Verify that no target binaries, data, extracted assets, audiovisual
   captures, save states, Ghidra databases, credentials, or absolute personal
   paths are present.
2. Verify `backend.lock.json` against the patch and upstream commit.
3. Run the contract tests on Windows and Linux.
4. Run `validate-project` for every included adapter.
5. Run `dos-re audit-public-tree .`.
6. Review every staged file with `git diff --cached --stat` and
   `git diff --cached`.
7. Do not publish until the staged file list contains only intentional toolkit
   files.

## New Repository

Do not use `Copy-Item -Recurse` on the working directory. It physically copies
ignored `.work` directories containing private specimens, captures, backend
binaries, and Ghidra databases into the publication directory. Git would
normally ignore those files, but they should never cross the export boundary.

From the `dos-re-harness` directory, create a new reviewed copy with Windows
`robocopy`. The destination must not already exist:

```powershell
$source = (Resolve-Path .).Path
$destination = Join-Path (Split-Path $source -Parent) `
  'dos-re-harness-public'
if (Test-Path -LiteralPath $destination) {
    throw "Refusing to overwrite existing destination: $destination"
}

robocopy $source $destination /E /XJ /R:1 /W:1 `
  /XD .git .work .agents .venv build dist __pycache__ `
      .pytest_cache CMakeFiles `
  /XF *.pyc
if ($LASTEXITCODE -gt 7) {
    throw "robocopy failed with exit code $LASTEXITCODE"
}

Set-Location $destination
.\scripts\dos-re.ps1 audit-public-tree .
git init -b main
git add .
git diff --cached --stat
git diff --cached
git commit -m "Initial portable DOS reverse-engineering harness"
```

Review both staged-diff commands completely. Verify that no `.work` or original
game path appears in `git status --short` or `git ls-files`. Do not add a remote
or push until the staged-content and license audits pass.
If preserving selected toolkit history later becomes important, replace this
process with a path-filtered export from a clean clone.

## Checkpoint Format

Use an ordinary commit plus an annotated tag for each reproducible milestone:

```text
checkpoint-00-harness-bootstrap
checkpoint-01-original-state-capture
checkpoint-02-first-zero-diff-state
checkpoint-03-first-zero-diff-frame
checkpoint-04-scripted-scene
checkpoint-05-portable-reimplementation
```

Each checkpoint should record:

- objective and known fidelity gap;
- specimen hashes without specimen content;
- backend lock and tool versions;
- exact scenario or input movie;
- commands needed to reproduce the result;
- state, frame, trace, and timing metrics;
- remaining divergence and its suspected cause.

Publish evidence manifests and numeric comparison reports. Do not publish
proprietary framebuffers, screenshots, audio, assets, save states, or memory
dumps without a separate rights review.

Use freely redistributable examples for public continuous integration. A
proprietary target can retain reproducible scripts and hashes while requiring
the user to provide their own original files.
