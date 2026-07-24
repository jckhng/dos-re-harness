param(
    [string]$ForkDir = ".work\dosbox-x-remotedebug",
    [switch]$Build
)

$ErrorActionPreference = "Stop"
$expectedCommit = "2917cb31e00a9d0a935060ac9186c1a7885da0fd"
$upstream = "https://github.com/lokkju/dosbox-x-remotedebug.git"
$toolkitRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$forkPath = if ([System.IO.Path]::IsPathRooted($ForkDir)) {
    [System.IO.Path]::GetFullPath($ForkDir)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $toolkitRoot $ForkDir))
}
$patchPath = Join-Path $toolkitRoot `
    "backends\dosbox-x-remotedebug\dosbox-x-remotedebug.patch"

if (-not (Test-Path -LiteralPath (Join-Path $forkPath ".git"))) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $forkPath) |
        Out-Null
    & git clone $upstream $forkPath
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to clone $upstream"
    }
    & git -C $forkPath checkout --detach $expectedCommit
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to check out backend commit $expectedCommit"
    }
}

$safeForkPath = $forkPath -replace "\\", "/"
$head = (
    & git -c "safe.directory=$safeForkPath" -C $forkPath rev-parse HEAD
).Trim()
if ($LASTEXITCODE -ne 0 -or $head -ne $expectedCommit) {
    throw "Expected backend commit $expectedCommit, found $head"
}

& git -c "safe.directory=$safeForkPath" -C $forkPath apply --check $patchPath `
    2>$null
if ($LASTEXITCODE -eq 0) {
    & git -c "safe.directory=$safeForkPath" -C $forkPath apply $patchPath
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to apply $patchPath"
    }
    Write-Host "Applied the pinned DOSBox-X harness patch."
} else {
    & git -c "safe.directory=$safeForkPath" -C $forkPath apply --reverse `
        --check $patchPath 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Backend is neither clean nor patched exactly as expected."
    }
    Write-Host "The pinned DOSBox-X harness patch is already applied."
}

if ($Build) {
    if ($forkPath -notmatch "^([A-Za-z]):\\(.*)$") {
        throw "The WSL build adapter requires a Windows drive path: $forkPath"
    }
    $forkWsl = "/mnt/{0}/{1}" -f $Matches[1].ToLowerInvariant(),
        ($Matches[2] -replace "\\", "/")
    & wsl.exe --exec bash -lc 'cd "$1" && ./build-debug --enable-remotedebug' `
        dos-re-build $forkWsl
    if ($LASTEXITCODE -ne 0) {
        throw "WSL DOSBox-X build failed"
    }
}
