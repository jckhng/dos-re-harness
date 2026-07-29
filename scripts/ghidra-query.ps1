param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("decompile", "instructions", "xrefs", "functions", "programs", "scalar", "custom")]
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
    [string]$TempRoot = "",
    [string]$CustomScript = "",
    [string[]]$AdditionalScriptPath = @(),
    [string]$JavaHome = "",
    [string]$OutputPath = "",
    [switch]$NoAnalysis
)

$ErrorActionPreference = "Stop"
$toolkitRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$genericScriptPath = Join-Path $toolkitRoot "ghidra\scripts"
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
    "custom" {
        if ([string]::IsNullOrWhiteSpace($CustomScript)) {
            throw "-CustomScript is required when -Query custom is selected"
        }
        $CustomScript
    }
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
$oldJavaHome = $env:JAVA_HOME
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
    if (-not [string]::IsNullOrWhiteSpace($JavaHome)) {
        if (-not (Test-Path -LiteralPath $JavaHome -PathType Container)) {
            throw "Missing Java home: $JavaHome"
        }
        $env:JAVA_HOME = (Resolve-Path $JavaHome).Path
    }

    $scriptPaths = if ($Query -eq "custom") {
        @()
    } else {
        @($genericScriptPath)
    }
    foreach ($path in $AdditionalScriptPath) {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            throw "Missing Ghidra script directory: $path"
        }
        $scriptPaths += (Resolve-Path $path).Path
    }
    if ($scriptPaths.Count -eq 0) {
        throw "No Ghidra script directory was configured"
    }
    $scriptPath = $scriptPaths -join [IO.Path]::PathSeparator
    $headlessArgs = @(
        (Resolve-Path $ProjectDir).Path,
        $ProjectName,
        "-process",
        $Program,
        "-scriptPath",
        $scriptPath
    )
    if ($NoAnalysis) {
        $headlessArgs += "-noanalysis"
    }
    $headlessArgs += @("-postScript", $script) + $Args

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        & $GhidraHeadless @headlessArgs
        exit $LASTEXITCODE
    }

    $resolvedOutput = [IO.Path]::GetFullPath($OutputPath)
    $outputDirectory = Split-Path -Parent $resolvedOutput
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
    $temporaryOutput = "$resolvedOutput.partial"
    if (Test-Path -LiteralPath $resolvedOutput) {
        throw "Refusing to overwrite Ghidra evidence: $resolvedOutput"
    }
    if (Test-Path -LiteralPath $temporaryOutput) {
        throw "Incomplete Ghidra evidence already exists: $temporaryOutput"
    }
    & $GhidraHeadless @headlessArgs 2>&1 |
        Tee-Object -FilePath $temporaryOutput
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "Ghidra headless query failed with exit code $exitCode; partial output: $temporaryOutput"
    }
    if (-not (Test-Path -LiteralPath $temporaryOutput -PathType Leaf) -or
        (Get-Item -LiteralPath $temporaryOutput).Length -eq 0) {
        throw "Ghidra headless query produced no evidence: $temporaryOutput"
    }
    Move-Item -LiteralPath $temporaryOutput -Destination $resolvedOutput
    Write-Host "wrote $resolvedOutput"
    exit 0
} finally {
    $env:USERPROFILE = $oldUserProfile
    $env:APPDATA = $oldAppData
    $env:LOCALAPPDATA = $oldLocalAppData
    $env:JAVA_TOOL_OPTIONS = $oldJavaToolOptions
    $env:JAVA_HOME = $oldJavaHome
}
