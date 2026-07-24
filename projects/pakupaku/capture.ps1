param(
    [Parameter(Mandatory = $true)]
    [string]$Scenario,
    [Parameter(Mandatory = $true)]
    [string]$OutDir,
    [string]$StartupSequence = "",
    [string]$WaitState = ""
)

$ErrorActionPreference = "Stop"

$projectDir = $PSScriptRoot
$toolkitRoot = (Resolve-Path (Join-Path $projectDir "..\..")).Path
$specimenDir = Join-Path $projectDir ".work\specimen\paku-1.6"
$backend = Join-Path $toolkitRoot ".work\backend-bin\dosbox-x"
$stateSchema = Join-Path $projectDir "state.schema.json"
$screenSignatures = Join-Path $projectDir "screens.json"

& (Join-Path $projectDir "verify-specimen.ps1") -SpecimenDir $specimenDir
if (-not $?) {
    throw "Paku Paku specimen verification failed"
}
if (-not (Test-Path -LiteralPath $backend -PathType Leaf)) {
    throw "Missing pinned DOSBox-X backend: $backend"
}

$arguments = @{
    OutDir = $OutDir
    Program = "PAKU.EXE"
    ProgramArguments = "/speaker"
    MountDir = $specimenDir
    Machine = "cga"
    CpuType = "auto"
    Cycles = "fixed 3000"
    DelaySeconds = 0.1
    StartupDelaySeconds = 1.0
    StartupSequence = $StartupSequence
    DumpSegment = "ds"
    DumpSize = 0x10000
    UseCleanMount = $true
    Screenshot = $true
    StateSchema = $stateSchema
    ScreenSignatures = $screenSignatures
    DosboxBinary = $backend
    RuntimeName = "pakupaku_$Scenario"
    VgaAddress = 0xB8000
    VgaWidth = 160
    VgaHeight = 100
}
if ($WaitState.Trim().Length -gt 0) {
    $arguments.WaitState = $WaitState.Split(";")
}

& (Join-Path $toolkitRoot "scripts\run-wsl-remotedebug.ps1") @arguments
exit $LASTEXITCODE