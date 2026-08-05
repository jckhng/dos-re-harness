[CmdletBinding(PositionalBinding = $false)]
param(
    [Alias("out")]
    [string]$CliOutPath,

    [Alias("help")]
    [switch]$CliHelp,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$HarnessArgs
)

$ErrorActionPreference = "Stop"
$toolkitRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$env:PYTHONPATH = Join-Path $toolkitRoot "src"
if ($PSBoundParameters.ContainsKey("CliOutPath")) {
    $HarnessArgs += @("--out", $CliOutPath)
}
if ($CliHelp) {
    $HarnessArgs += "--help"
}
& python -m dos_re_harness.cli @HarnessArgs
exit $LASTEXITCODE
