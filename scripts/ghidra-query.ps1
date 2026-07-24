param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("decompile", "instructions", "xrefs", "functions", "programs", "scalar")]
    [string]$Query,
    [Parameter(Mandatory = $true)]
    [string]$GhidraHeadless,
    [Parameter(Mandatory = $true)]
    [string]$ProjectDir,
    [Parameter(Mandatory = $true)]
    [string]$ProjectName,
    [Parameter(Mandatory = $true)]
    [string]$Program,
    [string[]]$Args = @(),
    [string]$TempRoot = ""
)

$ErrorActionPreference = "Stop"
$toolkitRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$scriptPath = Join-Path $toolkitRoot "ghidra\scripts"
if ($TempRoot.Trim().Length -eq 0) {
    $TempRoot = Join-Path $toolkitRoot ".work\ghidra"
}

$script = switch ($Query) {
    "decompile" { "DumpFunctionDecomp.java" }
    "instructions" { "DumpInstructions.java" }
    "xrefs" { "FindFunctionXrefs.java" }
    "functions" { "ListFunctionsStdout.java" }
    "programs" { "ListProgramsStdout.java" }
    "scalar" { "FindScalarUsage.java" }
}

if (-not (Test-Path -LiteralPath $GhidraHeadless)) {
    throw "Missing Ghidra headless launcher: $GhidraHeadless"
}

$userHome = Join-Path $TempRoot "userhome"
$appData = Join-Path $TempRoot "appdata"
$localAppData = Join-Path $TempRoot "localappdata"
New-Item -ItemType Directory -Force -Path $userHome, $appData, $localAppData | Out-Null

$oldUserProfile = $env:USERPROFILE
$oldAppData = $env:APPDATA
$oldLocalAppData = $env:LOCALAPPDATA
$oldJavaToolOptions = $env:JAVA_TOOL_OPTIONS
try {
    $env:USERPROFILE = (Resolve-Path $userHome).Path
    $env:APPDATA = (Resolve-Path $appData).Path
    $env:LOCALAPPDATA = (Resolve-Path $localAppData).Path
    $homeOption = "-Duser.home=$($env:USERPROFILE)"
    $env:JAVA_TOOL_OPTIONS = if ([string]::IsNullOrWhiteSpace($oldJavaToolOptions)) {
        $homeOption
    } else {
        "$oldJavaToolOptions $homeOption"
    }

    & $GhidraHeadless `
        (Resolve-Path $ProjectDir).Path `
        $ProjectName `
        -process $Program `
        -scriptPath $scriptPath `
        -postScript $script @Args
    exit $LASTEXITCODE
} finally {
    $env:USERPROFILE = $oldUserProfile
    $env:APPDATA = $oldAppData
    $env:LOCALAPPDATA = $oldLocalAppData
    $env:JAVA_TOOL_OPTIONS = $oldJavaToolOptions
}
