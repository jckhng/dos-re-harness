param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$HarnessArgs
)

$ErrorActionPreference = "Stop"
$toolkitRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$env:PYTHONPATH = Join-Path $toolkitRoot "src"
& python -m dos_re_harness.cli @HarnessArgs
exit $LASTEXITCODE
