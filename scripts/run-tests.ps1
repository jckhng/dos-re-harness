param(
    [string]$Python = "python",
    [string]$TempRoot = "",
    [string]$Pattern = "test*.py",
    [string]$DependencyPath = ""
)
$ErrorActionPreference = "Stop"
$arguments = @("-B", (Join-Path $PSScriptRoot "run_tests.py"), "--pattern", $Pattern)
if ($TempRoot) { $arguments += @("--temp-root", $TempRoot) }
if ($DependencyPath) { $arguments += @("--dependency-path", $DependencyPath) }
& $Python @arguments
exit $LASTEXITCODE
