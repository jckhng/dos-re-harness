param(
    [string]$SpecimenDir = ""
)

$ErrorActionPreference = "Stop"

$projectDir = $PSScriptRoot
$manifestPath = Join-Path $projectDir "specimen-manifest.json"
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json

if ($SpecimenDir.Trim().Length -eq 0) {
    $SpecimenDir = Join-Path $projectDir ".work/specimen/paku-1.6"
}

$root = (Resolve-Path -LiteralPath $SpecimenDir).Path
$errors = [System.Collections.Generic.List[string]]::new()
$expectedNames = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

foreach ($entry in $manifest.files) {
    [void]$expectedNames.Add([string]$entry.path)
    $path = Join-Path $root ([string]$entry.path)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $errors.Add("missing: $($entry.path)")
        continue
    }

    $item = Get-Item -LiteralPath $path
    if ($item.Length -ne [long]$entry.size) {
        $errors.Add(
            "size: $($entry.path) expected=$($entry.size) actual=$($item.Length)"
        )
    }

    $actualHash = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $path
    ).Hash.ToLowerInvariant()
    if ($actualHash -ne ([string]$entry.sha256).ToLowerInvariant()) {
        $errors.Add(
            "sha256: $($entry.path) expected=$($entry.sha256) actual=$actualHash"
        )
    }
}

foreach ($item in Get-ChildItem -File -LiteralPath $root) {
    if (-not $expectedNames.Contains($item.Name)) {
        $errors.Add("unexpected: $($item.Name)")
    }
}

foreach ($entry in $manifest.mutable_files) {
    if ($entry.baseline -eq "absent") {
        $path = Join-Path $root ([string]$entry.path)
        if (Test-Path -LiteralPath $path) {
            $errors.Add("mutable baseline must be absent: $($entry.path)")
        }
    }
}

foreach ($errorMessage in $errors) {
    Write-Error $errorMessage
}
if ($errors.Count -gt 0) {
    exit 1
}

Write-Output (
    "VALID specimen={0} files={1} mutable_absent={2}" -f
    $manifest.id,
    $manifest.files.Count,
    $manifest.mutable_files.Count
)
