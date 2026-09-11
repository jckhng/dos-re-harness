param(
    [string]$OutDir = "captures\dosbox\remote-runtime",
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[A-Za-z0-9_.-]+$")]
    [string]$Program,
    [string]$ProgramArguments = "",
    [Parameter(Mandatory = $true)]
    [string]$MountDir,
    [ValidatePattern("^[A-Za-z0-9_.-]+$")]
    [string]$Machine = "svga_s3",
    [ValidatePattern("^[A-Za-z0-9_.-]+$")]
    [string]$CpuType = "386",
    [string]$Cycles = "fixed 5000",
    [switch]$Turbo,
    [double]$DelaySeconds = 4.0,
    [double]$StartupDelaySeconds = 3.0,
    [string]$StartupSequence = "",
    [string]$InputScript = "",
    [string]$BackendInputScript = "",
    [string[]]$StartupKey = @(),
    [string[]]$Poke = @(),
    [string[]]$PokeFile = @(),
    [string]$RestoreRegisters = "",
    [string]$ResumeCheckpointScript = "",
    [string]$ResumeNextLinear = "",
    [string]$ResumeSideBreakSegmented = "",
    [int]$ResumeSideBreakMaxHits = 0,
    [int]$ResumeSideBreakStartValue = 0,
    [string[]]$ResumeSideBreakPoke = @(),
    [string]$PostResumeBreakLinear = "",
    [string]$PostResumeBreakSegmented = "",
    [int]$PostResumeBreakHitCount = 1,
    [string]$PostResumeBreakHitSeries = "",
    [int]$PostResumeDisplayHistoryCapacity = 0,
    [string[]]$PostResumePoke = @(),
    [string[]]$PostResumePokeFile = @(),
    [switch]$PostResumeContinueAfterPoke,
    [switch]$PostResumeContinue,
    [string]$PostResumeNextBreakLinear = "",
    [string]$PostResumeNextBreakSegmented = "",
    [int]$PostResumeNextBreakHitCount = 1,
    [string]$PostResumeNextBreakHitSeries = "",
    [string]$CallNear = "",
    [string]$CallNearBreakLinear = "",
    [string]$CallNearBreakSegmented = "",
    [string]$CallNearBreakOffset = "",
    [switch]$CallNearContinueAfterReturn,
    [string]$BreakpointLinear = "",
    [switch]$HaltAfterPoke,
    [string]$PostRestoreSequence = "",
    [string[]]$PostRestoreKey = @(),
    [string[]]$PostWaitKey = @(),
    [string[]]$WaitState = @(),
    [double]$WaitStateTimeout = 30.0,
    [double]$WaitStateInterval = 0.05,
    [ValidateRange(0.1, 3600.0)]
    [double]$RemoteTimeout = 10.0,
    [int]$VgaSequenceFrames = 0,
    [double]$VgaSequenceInterval = (1.0 / 70.0),
    [int]$DisplaySequenceFrames = 0,
    [double]$DisplaySequenceInterval = (1.0 / 70.0),
    [string]$VgaSequenceStopSha256 = "",
    [switch]$VgaSequenceScreenshotOnStop,
    [switch]$VgaSequenceScreenshotAll,
    [uint32]$VgaAddress = 0xA0000,
    [int]$VgaWidth = 320,
    [int]$VgaHeight = 200,
    [ValidateSet("ds", "ss")]
    [string]$DumpSegment = "ss",
    [int]$DumpSize = 0x4e00,
    [switch]$UseCleanMount,
    [string[]]$RestoreTrackedFile = @(),
    [switch]$Screenshot,
    [switch]$DumpLowMemory,
    [switch]$OmitCheckpointVga,
    [switch]$CheckpointDac,
    [switch]$CheckpointDisplayDump,
    [switch]$CheckpointScreenshot,
    [string[]]$CheckpointScreenshotPreserveMemory = @(),
    [switch]$CheckpointSaveState,
    [switch]$CheckpointSaveStateFirst,
    [string]$LoadSaveState = "",
    [switch]$LoadSaveStateContinue,
    [switch]$LoadSaveStatePaused,
    [string]$LoadSaveStateReadyScreen = "",
    [double]$LoadSaveStateReadyTimeout = 45.0,
    [switch]$CaptureAudio,
    [switch]$CaptureSfxOnly,
    [string]$OplLogPath = "",
    [string]$OplTickLinear = "",
    [string]$OplTickDsOffset = "",
    [string]$StateInputHookLinear = "",
    [string]$StateInputLinear = "",
    [string]$StateInputHookOffset = "",
    [string]$StateInputDsOffset = "",
    [string]$StateInputHookOffsetAlt = "",
    [ValidateSet(1, 2, 4)]
    [int]$StateInputWidth = 2,
    [string]$StateInputLogPath = "",
    [string]$StateInputTracePath = "",
    [string]$StateInputStopValue = "",
    [string]$StateInputWriteOffset = "",
    [string]$StateInputWriteLinear = "",
    [string]$StateInputWriteValue = "",
    [ValidateSet(1, 2, 4)]
    [int]$StateInputWriteWidth = 2,
    [switch]$StateInputObserveOnly,
    [switch]$CaptureVideo,
    [string]$CheckpointPostDisplayBreakSegmented = "",
    [string]$CheckpointPostDisplayPoke = "",
    [double]$CheckpointPostDisplayDelay = 0.05,
    [ValidateSet("all", "post-resume-next")]
    [string]$CheckpointPostDisplayScope = "all",
    [string]$FinalPostDisplayBreakSegmented = "",
    [string]$FinalPostDisplayPoke = "",
    [double]$FinalPostDisplayDelay = 0.05,
    [Parameter(Mandatory = $true)]
    [string]$StateSchema,
    [Parameter(Mandatory = $true)]
    [string]$ScreenSignatures,
    [string]$WorkspaceRoot = "",
    [Parameter(Mandatory = $true)]
    [string]$DosboxBinary,
    [ValidatePattern("^[A-Za-z0-9_.-]+$")]
    [string]$RuntimeName = "dos_re_runtime",
    [ValidateRange(0, 65535)]
    [int]$GdbPort = 0,
    [ValidateRange(0, 65535)]
    [int]$QmpPort = 0,
    [switch]$KeepRunning
)

$ErrorActionPreference = "Stop"

function Resolve-WorkspacePath {
    param(
        [Parameter(Mandatory = $true)][string]$WorkspaceRoot,
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$AllowMissing
    )

    $candidate = if ([System.IO.Path]::IsPathRooted($Path)) {
        $Path
    } else {
        Join-Path $WorkspaceRoot $Path
    }
    if ($AllowMissing) {
        return [System.IO.Path]::GetFullPath($candidate)
    }
    return (Resolve-Path -LiteralPath $candidate).Path
}

function Convert-WindowsPathToWsl {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path -notmatch "^([A-Za-z]):\\(.*)$") {
        throw "Expected a Windows drive path, got: $Path"
    }
    $drive = $Matches[1].ToLowerInvariant()
    $rest = $Matches[2] -replace "\\", "/"
    return "/mnt/$drive/$rest"
}

function Test-RemoteDebugPort {
    param(
        [Parameter(Mandatory = $true)][int]$Port
    )

    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener(
            [System.Net.IPAddress]::Loopback,
            $Port
        )
        $listener.Start()
        return $true
    }
    catch [System.Net.Sockets.SocketException] {
        return $false
    }
    finally {
        if ($null -ne $listener) {
            $listener.Stop()
        }
    }
}

function Resolve-RemoteDebugPorts {
    param(
        [Parameter(Mandatory = $true)][ValidatePattern("^[A-Za-z0-9_.-]+$")]
        [string]$Name,
        [Parameter(Mandatory = $true)][ValidateRange(0, 65535)]
        [int]$RequestedGdbPort,
        [Parameter(Mandatory = $true)][ValidateRange(0, 65535)]
        [int]$RequestedQmpPort
    )

    if ($RequestedGdbPort -eq 0 -and $RequestedQmpPort -eq 0) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($Name)
            $digest = $sha.ComputeHash($bytes)
        }
        finally {
            $sha.Dispose()
        }
        $seed = [BitConverter]::ToUInt16($digest, 0)
        $candidate = 20000 + ($seed % 20000)
        for ($attempt = 0; $attempt -lt 10000; ++$attempt) {
            $gdb = $candidate + 2 * $attempt
            $qmp = $gdb + 1
            if ($qmp -gt 65535) {
                break
            }
            if ((Test-RemoteDebugPort $gdb) -and
                (Test-RemoteDebugPort $qmp)) {
                return @{ GdbPort = $gdb; QmpPort = $qmp; Automatic = $true }
            }
        }
        throw "Unable to allocate isolated GDB/QMP ports for runtime '$Name'"
    }

    $gdb = $RequestedGdbPort
    $qmp = $RequestedQmpPort
    if ($gdb -eq 0) {
        $gdb = $qmp - 1
    }
    if ($qmp -eq 0) {
        $qmp = $gdb + 1
    }
    if ($gdb -lt 1 -or $qmp -lt 1 -or $gdb -gt 65535 -or
        $qmp -gt 65535 -or $gdb -eq $qmp) {
        throw "GDB and QMP ports must be distinct values in the range 1..65535"
    }
    if (-not (Test-RemoteDebugPort $gdb) -or
        -not (Test-RemoteDebugPort $qmp)) {
        throw "Requested GDB/QMP ports are unavailable: $gdb/$qmp"
    }
    return @{ GdbPort = $gdb; QmpPort = $qmp; Automatic = $false }
}

function Convert-PokeFileSpecToWsl {
    param(
        [Parameter(Mandatory = $true)][string]$Spec
    )

    if ($Spec.StartsWith("ds:") -or $Spec.StartsWith("ss:")) {
        $parts = $Spec.Split(":", 3)
        if ($parts.Count -ne 3) {
            throw "PokeFile must be ds:offset:path / ss:offset:path, got '$Spec'"
        }
        return (
            $parts[0] + ":" + $parts[1] + ":" +
            (Convert-WindowsPathToWsl (Resolve-Path $parts[2]).Path)
        )
    }
    $separator = $Spec.IndexOf(":")
    if ($separator -lt 0) {
        throw "PokeFile must be linear:path or ds:offset:path / ss:offset:path, got '$Spec'"
    }
    $address = $Spec.Substring(0, $separator)
    $path = $Spec.Substring($separator + 1)
    return (
        $address + ":" +
        (Convert-WindowsPathToWsl (Resolve-Path $path).Path)
    )
}

function Export-GitBlob {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$GitPath,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if ($GitPath -notmatch "^[A-Za-z0-9_./-]+$") {
        throw "Tracked file path contains unsupported characters: $GitPath"
    }

    $gitExe = (Get-Command git -ErrorAction Stop).Source
    $repoRootGit = $RepositoryRoot -replace "\\", "/"
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $gitExe
    $startInfo.Arguments = '-c safe.directory="{0}" -C "{1}" cat-file blob "HEAD:{2}"' -f `
        $repoRootGit, $RepositoryRoot, $GitPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Failed to start Git while restoring $GitPath"
    }
    try {
        $output = [System.IO.File]::Create($Destination)
        try {
            $process.StandardOutput.BaseStream.CopyTo($output)
        }
        finally {
            $output.Dispose()
        }
        $errorText = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
            throw "Failed to restore HEAD:$GitPath`: $errorText"
        }
    }
    finally {
        $process.Dispose()
    }
}

$toolkitRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$repoRoot = if ($WorkspaceRoot.Trim().Length -gt 0) {
    (Resolve-Path -LiteralPath $WorkspaceRoot).Path
} else {
    (Resolve-Path (Join-Path $toolkitRoot "..")).Path
}
$outPath = Resolve-WorkspacePath $repoRoot $OutDir -AllowMissing
New-Item -ItemType Directory -Force -Path $outPath | Out-Null
$remoteDebugPorts = Resolve-RemoteDebugPorts `
    -Name $RuntimeName `
    -RequestedGdbPort $GdbPort `
    -RequestedQmpPort $QmpPort
$GdbPort = $remoteDebugPorts.GdbPort
$QmpPort = $remoteDebugPorts.QmpPort

$repoRootWsl = Convert-WindowsPathToWsl $repoRoot
$mountPath = Resolve-WorkspacePath $repoRoot $MountDir
$sourceMountPath = $mountPath
if ($UseCleanMount) {
    $cleanMountPath = Join-Path $outPath "_game"
    New-Item -ItemType Directory -Force -Path $cleanMountPath | Out-Null
    Copy-Item -Path (Join-Path $sourceMountPath "*") -Destination $cleanMountPath -Recurse -Force
    $cleanMountRoot = [System.IO.Path]::GetFullPath($cleanMountPath)
    $cleanMountPrefix = $cleanMountRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    foreach ($spec in $RestoreTrackedFile) {
        $separator = $spec.IndexOf("=")
        if ($separator -le 0 -or $separator -eq ($spec.Length - 1)) {
            throw "RestoreTrackedFile must be repository/path=mount/path, got '$spec'"
        }
        $gitPath = $spec.Substring(0, $separator).Trim()
        $relativeDestination = $spec.Substring($separator + 1).Trim()
        if ([System.IO.Path]::IsPathRooted($relativeDestination)) {
            throw "RestoreTrackedFile destination must be relative: $relativeDestination"
        }
        $destination = [System.IO.Path]::GetFullPath(
            (Join-Path $cleanMountRoot $relativeDestination)
        )
        if (-not $destination.StartsWith(
            $cleanMountPrefix,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw "RestoreTrackedFile destination escapes clean mount: $relativeDestination"
        }
        $destinationParent = Split-Path -Parent $destination
        New-Item -ItemType Directory -Force -Path $destinationParent | Out-Null
        Export-GitBlob $repoRoot $gitPath $destination
        if ((Get-Item -LiteralPath $destination).Length -le 0) {
            throw "Restored tracked file is empty: $gitPath"
        }
    }
    if ($RestoreTrackedFile.Count -gt 0) {
        Write-Host "Restored $($RestoreTrackedFile.Count) tracked file(s) into clean mount."
    }
    $mountPath = (Resolve-Path $cleanMountPath).Path
} elseif ($RestoreTrackedFile.Count -gt 0) {
    throw "RestoreTrackedFile requires UseCleanMount"
}
$mountPathWsl = Convert-WindowsPathToWsl $mountPath
$outPathWsl = Convert-WindowsPathToWsl (Resolve-Path $outPath).Path
if ($StartupSequence.Trim().Length -gt 0) {
    $StartupKey = $StartupSequence.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 }
}
if ($PostRestoreSequence.Trim().Length -gt 0) {
    $PostRestoreKey = $PostRestoreSequence.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 }
}
$WaitState = @(
    foreach ($spec in $WaitState) {
        $spec.Split(";") | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 }
    }
)
$keep = if ($KeepRunning) { "1" } else { "0" }
$screenshotArg = if ($Screenshot) { "1" } else { "0" }
$haltAfterPokeArg = if ($HaltAfterPoke) { "1" } else { "0" }
$dumpLowMemoryArg = if ($DumpLowMemory) { "1" } else { "0" }
$omitCheckpointVgaArg = if ($OmitCheckpointVga) { "1" } else { "0" }
$checkpointScreenshotArg = if ($CheckpointScreenshot) { "1" } else { "0" }
$checkpointSaveStateArg = if ($CheckpointSaveState) { "1" } else { "0" }
$captureAudioArg = if ($CaptureAudio -or $CaptureSfxOnly) { "1" } else { "0" }
$captureSfxOnlyArg = if ($CaptureSfxOnly) { "1" } else { "0" }
$captureVideoArg = if ($CaptureVideo) { "1" } else { "0" }
$vgaSequenceScreenshotOnStopArg = if (
    $VgaSequenceScreenshotOnStop
) { "1" } else { "0" }
$checkpointPostDisplayBreakSegmentedArg = if (
    $CheckpointPostDisplayBreakSegmented.Trim().Length -gt 0
) { $CheckpointPostDisplayBreakSegmented } else { "__none__" }
$checkpointPostDisplayPokeArg = if (
    $CheckpointPostDisplayPoke.Trim().Length -gt 0
) { $CheckpointPostDisplayPoke } else { "__none__" }
$finalPostDisplayBreakSegmentedArg = if (
    $FinalPostDisplayBreakSegmented.Trim().Length -gt 0
) { $FinalPostDisplayBreakSegmented } else { "__none__" }
$finalPostDisplayPokeArg = if (
    $FinalPostDisplayPoke.Trim().Length -gt 0
) { $FinalPostDisplayPoke } else { "__none__" }
$stateSchemaPath = Resolve-WorkspacePath $repoRoot $StateSchema
$screenSignaturesPath = Resolve-WorkspacePath $repoRoot $ScreenSignatures
$stateSchemaWsl = Convert-WindowsPathToWsl $stateSchemaPath
$screenSignaturesWsl = Convert-WindowsPathToWsl $screenSignaturesPath
$toolkitRootWsl = Convert-WindowsPathToWsl $toolkitRoot
$dosboxBinaryWsl = Convert-WindowsPathToWsl (Resolve-WorkspacePath $repoRoot $DosboxBinary)

$bash = @'
set -euo pipefail

repo="$1"
out_dir="$2"
program="$3"
mount_dir="$4"
delay_seconds="$5"
startup_delay_seconds="$6"
dump_size="$7"
dump_segment="$8"
keep="$9"
screenshot="${10}"
wait_state_timeout="${11}"
wait_state_interval="${12}"
restore_registers="${13}"
halt_after_poke="${14}"
dump_low_memory="${15}"
call_near="${16}"
vga_sequence_frames="${17}"
vga_sequence_interval="${18}"
vga_sequence_stop_sha256="${19}"
capture_audio="${20}"
capture_sfx_only="${21}"
state_schema="${22}"
screen_signatures="${23}"
toolkit="${24}"
dosbox="${25}"
runtime_name="${26}"
machine="${27}"
cpu_type="${28}"
cycles="${29}"
program_arguments="${30}"
vga_address="${31}"
vga_width="${32}"
vga_height="${33}"
break_linear="${34}"
input_script="${35}"
resume_checkpoint_script="${36}"
resume_next_linear="${37}"
omit_checkpoint_vga="${38}"
checkpoint_screenshot="${39}"
post_resume_break_linear="${40}"
post_resume_break_hit_count="${41}"
post_resume_break_segmented="${42}"
post_resume_next_break_linear="${43}"
post_resume_next_break_hit_count="${44}"
post_resume_next_break_segmented="${45}"
post_resume_break_hit_series="${46}"
post_resume_continue_after_poke="${47}"
post_resume_continue="0"
checkpoint_save_state="${48}"
load_save_state="${49}"
load_save_state_ready_screen="${50}"
load_save_state_ready_timeout="${51}"
capture_video="${52}"
checkpoint_post_display_break_segmented="${53}"
checkpoint_post_display_poke="${54}"
checkpoint_post_display_delay="${55}"
resume_side_break_segmented="${56}"
resume_side_break_max_hits="${57}"
resume_side_break_start_value="${58}"
opl_log_path="${59}"
opl_tick_linear="${60}"
call_near_continue_after_return="${61}"
remote_timeout="${62}"
vga_sequence_screenshot_on_stop="${63}"
state_input_hook_linear="${64}"
state_input_linear="${65}"
state_input_width="${66}"
state_input_log_path="${67}"
turbo="${68}"
checkpoint_post_display_scope="${69}"
state_input_stop_value="${70}"
gdb_port="${71}"
qmp_port="${72}"
checkpoint_dac="${73}"
shift 70
shift 2
shift
opl_tick_ds_offset="__none__"
state_input_hook_offset="__none__"
state_input_ds_offset="__none__"
state_input_hook_offset_alt="__none__"
state_input_trace_path="__none__"
state_input_write_offset="__none__"
state_input_write_linear="__none__"
state_input_write_value="__none__"
state_input_write_width="2"
final_post_display_break_segmented="__none__"
final_post_display_poke="__none__"
final_post_display_delay="0.05"
final_post_display_value="__none__"
vga_sequence_screenshot_all="0"
call_near_break_linear="__none__"
call_near_break_segmented="__none__"
call_near_break_offset="__none__"
load_save_state_continue="0"
load_save_state_paused="0"
checkpoint_save_state_first="0"
post_resume_next_break_hit_series="__none__"
checkpoint_screenshot_preserve_memory=()
checkpoint_displaydump="0"
display_sequence_frames="0"
display_sequence_interval="0.0142857142857143"
post_resume_display_history_capacity="0"
state_input_observe_only="0"
backend_input_script="__same__"
filtered_args=()
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--backend-input-script" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--backend-input-script requires PATH" >&2
            exit 2
        fi
        backend_input_script="$2"
        shift 2
    elif [ "$1" = "--state-input-observe-only" ]; then
        state_input_observe_only="1"
        shift
    elif [ "$1" = "--load-save-state-continue" ]; then
        load_save_state_continue="1"
        shift
    elif [ "$1" = "--load-save-state-paused" ]; then
        load_save_state_paused="1"
        shift
    elif [ "$1" = "--checkpoint-save-state-first" ]; then
        checkpoint_save_state_first="1"
        shift
    elif [ "$1" = "--checkpoint-displaydump" ]; then
        checkpoint_displaydump="1"
        shift
    elif [ "$1" = "--display-sequence-frames" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--display-sequence-frames requires COUNT" >&2
            exit 2
        fi
        display_sequence_frames="$2"
        shift 2
    elif [ "$1" = "--display-sequence-interval" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--display-sequence-interval requires SECONDS" >&2
            exit 2
        fi
        display_sequence_interval="$2"
        shift 2
    elif [ "$1" = "--post-resume-display-history-capacity" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--post-resume-display-history-capacity requires COUNT" >&2
            exit 2
        fi
        post_resume_display_history_capacity="$2"
        shift 2
    elif [ "$1" = "--post-resume-continue" ]; then
        post_resume_continue="1"
        shift
    elif [ "$1" = "--post-resume-next-break-hit-series" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--post-resume-next-break-hit-series requires HITS" >&2
            exit 2
        fi
        post_resume_next_break_hit_series="$2"
        shift 2
    elif [ "$1" = "--checkpoint-screenshot-preserve-memory" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--checkpoint-screenshot-preserve-memory requires REGION" >&2
            exit 2
        fi
        checkpoint_screenshot_preserve_memory+=("$2")
        shift 2
    elif [ "$1" = "--call-near-break-linear" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--call-near-break-linear requires ADDRESS" >&2
            exit 2
        fi
        call_near_break_linear="$2"
        shift 2
    elif [ "$1" = "--vga-sequence-screenshot-all" ]; then
        vga_sequence_screenshot_all="1"
        shift
    elif [ "$1" = "--call-near-break-segmented" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--call-near-break-segmented requires SEGMENT:OFFSET" >&2
            exit 2
        fi
        call_near_break_segmented="$2"
        shift 2
    elif [ "$1" = "--call-near-break-offset" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--call-near-break-offset requires OFFSET" >&2
            exit 2
        fi
        call_near_break_offset="$2"
        shift 2
    elif [ "$1" = "--opl-tick-ds-offset" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--opl-tick-ds-offset requires OFFSET" >&2
            exit 2
        fi
        opl_tick_ds_offset="$2"
        shift 2
    elif [ "$1" = "--state-input-hook-offset" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--state-input-hook-offset requires OFFSET" >&2
            exit 2
        fi
        state_input_hook_offset="$2"
        shift 2
    elif [ "$1" = "--state-input-ds-offset" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--state-input-ds-offset requires OFFSET" >&2
            exit 2
        fi
        state_input_ds_offset="$2"
        shift 2
    elif [ "$1" = "--state-input-hook-offset-alt" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--state-input-hook-offset-alt requires OFFSET" >&2
            exit 2
        fi
        state_input_hook_offset_alt="$2"
        shift 2
    elif [ "$1" = "--state-input-trace" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--state-input-trace requires PATH" >&2
            exit 2
        fi
        state_input_trace_path="$2"
        shift 2
    elif [ "$1" = "--state-input-write-offset" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--state-input-write-offset requires OFFSET" >&2
            exit 2
        fi
        state_input_write_offset="$2"
        shift 2
    elif [ "$1" = "--state-input-write-linear" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--state-input-write-linear requires ADDRESS" >&2
            exit 2
        fi
        state_input_write_linear="$2"
        shift 2
    elif [ "$1" = "--state-input-write-value" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--state-input-write-value requires VALUE" >&2
            exit 2
        fi
        state_input_write_value="$2"
        shift 2
    elif [ "$1" = "--state-input-write-width" ]; then
        if [ "$#" -lt 2 ]; then
            echo "--state-input-write-width requires WIDTH" >&2
            exit 2
        fi
        state_input_write_width="$2"
        shift 2
    elif [ "$1" = "--final-post-display" ]; then
        if [ "$#" -lt 5 ]; then
            echo "--final-post-display requires BREAK POKE DELAY VALUE" >&2
            exit 2
        fi
        final_post_display_break_segmented="$2"
        final_post_display_poke="$3"
        final_post_display_delay="$4"
        final_post_display_value="$5"
        shift 5
    else
        filtered_args+=("$1")
        shift
    fi
done
set -- "${filtered_args[@]}"
if [ "$program_arguments" = "__none__" ]; then
    program_arguments=""
fi
startup_keys=()
poke_specs=()
poke_file_specs=()
post_restore_keys=()
post_wait_keys=()
wait_state_specs=()
post_resume_poke_specs=()
post_resume_poke_file_specs=()
state_side_break_poke_specs=()
parsing_pokes=0
parsing_poke_files=0
parsing_post_restore=0
parsing_post_wait=0
parsing_wait_state=0
parsing_post_resume_pokes=0
parsing_post_resume_poke_files=0
parsing_state_side_break_pokes=0
for arg in "$@"; do
    if [ "$arg" = "--" ] || [ "$arg" = "--pokes" ]; then
        parsing_pokes=1
        parsing_poke_files=0
        parsing_post_restore=0
        parsing_post_wait=0
        parsing_wait_state=0
        parsing_post_resume_pokes=0
        parsing_post_resume_poke_files=0
        continue
    fi
    if [ "$arg" = "--poke-files" ]; then
        parsing_pokes=0
        parsing_poke_files=1
        parsing_post_restore=0
        parsing_post_wait=0
        parsing_wait_state=0
        parsing_post_resume_pokes=0
        parsing_post_resume_poke_files=0
        continue
    fi
    if [ "$arg" = "--post-restore" ]; then
        parsing_pokes=0
        parsing_poke_files=0
        parsing_post_restore=1
        parsing_post_wait=0
        parsing_wait_state=0
        parsing_post_resume_pokes=0
        parsing_post_resume_poke_files=0
        continue
    fi
    if [ "$arg" = "--post-wait-key" ]; then
        parsing_pokes=0
        parsing_poke_files=0
        parsing_post_restore=0
        parsing_post_wait=1
        parsing_wait_state=0
        parsing_post_resume_pokes=0
        parsing_post_resume_poke_files=0
        continue
    fi
    if [ "$arg" = "--wait-state" ]; then
        parsing_pokes=0
        parsing_poke_files=0
        parsing_post_restore=0
        parsing_post_wait=0
        parsing_wait_state=1
        parsing_post_resume_pokes=0
        parsing_post_resume_poke_files=0
        continue
    fi
    if [ "$arg" = "--post-resume-pokes" ]; then
        parsing_pokes=0
        parsing_poke_files=0
        parsing_post_restore=0
        parsing_post_wait=0
        parsing_wait_state=0
        parsing_post_resume_pokes=1
        parsing_post_resume_poke_files=0
        continue
    fi
    if [ "$arg" = "--post-resume-poke-files" ]; then
        parsing_pokes=0
        parsing_poke_files=0
        parsing_post_restore=0
        parsing_post_wait=0
        parsing_wait_state=0
        parsing_post_resume_pokes=0
        parsing_post_resume_poke_files=1
        continue
    fi
    if [ "$arg" = "--state-side-break-pokes" ]; then
        parsing_pokes=0
        parsing_poke_files=0
        parsing_post_restore=0
        parsing_post_wait=0
        parsing_wait_state=0
        parsing_post_resume_pokes=0
        parsing_post_resume_poke_files=0
        parsing_state_side_break_pokes=1
        continue
    fi
    if [ "$parsing_state_side_break_pokes" = "1" ]; then
        state_side_break_poke_specs+=("$arg")
    elif [ "$parsing_post_resume_poke_files" = "1" ]; then
        post_resume_poke_file_specs+=("$arg")
    elif [ "$parsing_post_resume_pokes" = "1" ]; then
        post_resume_poke_specs+=("$arg")
    elif [ "$parsing_wait_state" = "1" ]; then
        wait_state_specs+=("$arg")
    elif [ "$parsing_post_restore" = "1" ]; then
        post_restore_keys+=("$arg")
    elif [ "$parsing_post_wait" = "1" ]; then
        post_wait_keys+=("$arg")
    elif [ "$parsing_poke_files" = "1" ]; then
        poke_file_specs+=("$arg")
    elif [ "$parsing_pokes" = "1" ]; then
        poke_specs+=("$arg")
    else
        startup_keys+=("$arg")
    fi
done
conf="/tmp/${runtime_name}.conf"
log="/tmp/${runtime_name}.log"
pidfile="/tmp/${runtime_name}.pid"

if [ ! -x "$dosbox" ]; then
    echo "Missing WSL DOSBox-X remotedebug binary: $dosbox" >&2
    exit 2
fi

if [ "$capture_audio" = "1" ]; then
    mixer_nosound=false
else
    mixer_nosound=true
fi
if [ "$capture_sfx_only" = "1" ]; then
    opl_mode=none
else
    opl_mode=opl2
fi

# DOSBox-X handles SIGTERM by opening an interactive quit confirmation when a
# DOS program is active. A stale headless capture must never block the next
# run on that invisible dialog.
pkill -9 -f "dosbox-x.*${runtime_name}.conf" >/dev/null 2>&1 || true
rm -f "$conf" "$log" "$pidfile"

cat > "$conf" <<EOF
[dosbox]
machine = $machine
gdbserver = true
gdbserver port = $gdb_port
qmpserver = true
qmpserver port = $qmp_port
captures = $out_dir

[cpu]
cputype = $cpu_type
core = normal
cycles = $cycles
turbo = $turbo
stop turbo on key = false

[sdl]
fullscreen = false
output = surface

[mouse]
int33 = false

[render]
aspect = true
scaler = none

[mixer]
nosound = $mixer_nosound
rate = 44100
blocksize = 1024
prebuffer = 25

[sblaster]
sbtype = sb16
sbbase = 220
irq = 7
dma = 1
hdma = 5
oplmode = $opl_mode
oplemu = nuked
oplrate = 44100

[joystick]
joysticktype = none

[debug]
debuggerrun = normal

[autoexec]
mount c $mount_dir
c:
$(if [ "$capture_video" = "1" ]; then
    printf 'DX-CAPTURE /V %s %s' "$program" "$program_arguments"
else
    printf '%s %s' "$program" "$program_arguments"
fi)
EOF

runtime_env=(SDL_VIDEODRIVER=dummy SDL_AUDIODRIVER=dummy)
if [ "$opl_log_path" != "__none__" ]; then
    runtime_env+=(DOS_RE_HARNESS_OPL_LOG="$opl_log_path")
fi
if [ "$opl_tick_linear" != "__none__" ]; then
    runtime_env+=(DOS_RE_HARNESS_OPL_TICK_LINEAR="$opl_tick_linear")
fi
if [ "$opl_tick_ds_offset" != "__none__" ]; then
    runtime_env+=(DOS_RE_HARNESS_OPL_TICK_DS_OFFSET="$opl_tick_ds_offset")
fi
if [ "$state_input_hook_linear" != "__none__" ] || [ "$state_input_hook_offset" != "__none__" ]; then
    runtime_env+=(DOS_RE_HARNESS_STATE_INPUT_WIDTH="$state_input_width")
    if [ "$input_script" != "__none__" ]; then
        if [ "$state_input_observe_only" != "1" ]; then
            if [ "$backend_input_script" = "__same__" ]; then
                runtime_env+=(DOS_RE_HARNESS_STATE_INPUT_SCRIPT="$input_script")
            else
                runtime_env+=(DOS_RE_HARNESS_STATE_INPUT_SCRIPT="$backend_input_script")
            fi
        fi
    fi
    if [ "$state_input_hook_offset" != "__none__" ]; then
        runtime_env+=(
            DOS_RE_HARNESS_STATE_INPUT_HOOK_OFFSET="$state_input_hook_offset"
            DOS_RE_HARNESS_STATE_INPUT_DS_OFFSET="$state_input_ds_offset"
        )
        if [ "$state_input_hook_offset_alt" != "__none__" ]; then
            runtime_env+=(
                DOS_RE_HARNESS_STATE_INPUT_HOOK_OFFSET_ALT="$state_input_hook_offset_alt"
            )
        fi
    else
        runtime_env+=(
            DOS_RE_HARNESS_STATE_INPUT_HOOK_LINEAR="$state_input_hook_linear"
            DOS_RE_HARNESS_STATE_INPUT_LINEAR="$state_input_linear"
        )
    fi
    if [ "$state_input_log_path" != "__none__" ]; then
        runtime_env+=(
            DOS_RE_HARNESS_STATE_INPUT_LOG="$state_input_log_path"
        )
    fi
    if [ "$state_input_trace_path" != "__none__" ]; then
        runtime_env+=(
            DOS_RE_HARNESS_STATE_INPUT_TRACE="$state_input_trace_path"
        )
    fi
fi
if [ "$state_input_stop_value" != "__none__" ]; then
    runtime_env+=(DOS_RE_HARNESS_STATE_INPUT_STOP_VALUE="$state_input_stop_value")
fi
if [ "$state_input_write_offset" != "__none__" ] || [ "$state_input_write_linear" != "__none__" ]; then
    if [ "$state_input_write_offset" != "__none__" ] && [ "$state_input_write_linear" != "__none__" ]; then
        echo "state-input write offset and linear address are mutually exclusive" >&2
        exit 2
    fi
    if [ "$state_input_write_value" = "__none__" ]; then
        echo "state-input write requires a value" >&2
        exit 2
    fi
    if [ "$state_input_write_offset" != "__none__" ]; then
        runtime_env+=(DOS_RE_HARNESS_STATE_INPUT_WRITE_OFFSET="$state_input_write_offset")
    else
        runtime_env+=(DOS_RE_HARNESS_STATE_INPUT_WRITE_LINEAR="$state_input_write_linear")
    fi
    runtime_env+=(
        DOS_RE_HARNESS_STATE_INPUT_WRITE_VALUE="$state_input_write_value"
        DOS_RE_HARNESS_STATE_INPUT_WRITE_WIDTH="$state_input_write_width"
    )
fi
nohup env "${runtime_env[@]}" "$dosbox" -conf "$conf" >"$log" 2>&1 &
pid="$!"
echo "$pid" > "$pidfile"

cleanup() {
    if [ "$keep" != "1" ] && kill -0 "$pid" >/dev/null 2>&1; then
        kill -9 "$pid" >/dev/null 2>&1 || true
        wait "$pid" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

controller_args=(
    --gdb-port "$gdb_port"
    --qmp-port "$qmp_port"
    --out-dir "$out_dir"
    --timeout "$remote_timeout"
    --startup-delay "$startup_delay_seconds"
    --delay "$delay_seconds"
    --dump-segment "$dump_segment"
    --dump-size "$dump_size"
    --wait-state-timeout "$wait_state_timeout"
    --wait-state-interval "$wait_state_interval"
    --vga-sequence-frames "$vga_sequence_frames"
    --vga-sequence-interval "$vga_sequence_interval"
    --state-schema "$state_schema"
    --screen-signatures "$screen_signatures"
    --vga-address "$vga_address"
    --vga-width "$vga_width"
    --vga-height "$vga_height"
)
if [ "$vga_sequence_stop_sha256" != "__none__" ]; then
    controller_args+=(--vga-sequence-stop-sha256 "$vga_sequence_stop_sha256")
fi
if [ "$vga_sequence_screenshot_on_stop" = "1" ]; then
    controller_args+=(--vga-sequence-screenshot-on-stop)
fi
if [ "$vga_sequence_screenshot_all" = "1" ]; then
    controller_args+=(--vga-sequence-screenshot-all)
fi
if [ "$break_linear" != "__none__" ]; then
    controller_args+=(--break-linear "$break_linear")
fi
if [ "$input_script" != "__none__" ]; then
    controller_args+=(--input-script "$input_script")
fi
for key in "${startup_keys[@]}"; do
    controller_args+=(--startup-key "$key")
done
for poke in "${poke_specs[@]}"; do
    controller_args+=(--poke "$poke")
done
for poke_file in "${poke_file_specs[@]}"; do
    controller_args+=(--poke-file "$poke_file")
done
for wait_state in "${wait_state_specs[@]}"; do
    controller_args+=(--wait-state "$wait_state")
done
for key in "${post_restore_keys[@]}"; do
    controller_args+=(--post-restore-key "$key")
done
for key in "${post_wait_keys[@]}"; do
    controller_args+=(--post-wait-key "$key")
done
for poke in "${state_side_break_poke_specs[@]}"; do
    controller_args+=(--state-side-break-poke "$poke")
done
if [ "$restore_registers" != "__none__" ]; then
    controller_args+=(--restore-registers "$restore_registers")
fi
if [ "$resume_checkpoint_script" != "__none__" ]; then
    controller_args+=(--resume-checkpoint-script "$resume_checkpoint_script")
    if [ "$input_script" != "__none__" ] && {
        [ "$state_input_hook_linear" != "__none__" ] ||
        [ "$state_input_hook_offset" != "__none__" ];
    }; then
        if [ "$state_input_observe_only" = "1" ]; then
            controller_args+=(--resume-script-event-owner controller)
        elif [ "$backend_input_script" != "__same__" ]; then
            controller_args+=(--resume-script-event-owner controller)
        else
            controller_args+=(--resume-script-event-owner backend)
        fi
    fi
fi
if [ "$resume_next_linear" != "__none__" ]; then
    controller_args+=(--resume-next-linear "$resume_next_linear")
fi
if [ "$post_resume_break_linear" != "__none__" ]; then
    controller_args+=(
        --post-resume-break-linear "$post_resume_break_linear"
        --post-resume-break-hit-count "$post_resume_break_hit_count"
    )
fi
if [ "$post_resume_break_segmented" != "__none__" ]; then
    controller_args+=(
        --post-resume-break-segmented "$post_resume_break_segmented"
        --post-resume-break-hit-count "$post_resume_break_hit_count"
    )
fi
if [ "$post_resume_break_hit_series" != "__none__" ]; then
    controller_args+=(
        --post-resume-break-hit-series "$post_resume_break_hit_series"
    )
fi
for poke in "${post_resume_poke_specs[@]}"; do
    controller_args+=(--post-resume-poke "$poke")
done
for poke_file in "${post_resume_poke_file_specs[@]}"; do
    controller_args+=(--post-resume-poke-file "$poke_file")
done
if [ "$post_resume_continue_after_poke" = "1" ]; then
    controller_args+=(--post-resume-continue-after-poke)
fi
if [ "$post_resume_continue" = "1" ]; then
    controller_args+=(--post-resume-continue)
fi
if [ "$post_resume_next_break_linear" != "__none__" ]; then
    controller_args+=(
        --post-resume-next-break-linear "$post_resume_next_break_linear"
        --post-resume-next-break-hit-count "$post_resume_next_break_hit_count"
    )
fi
if [ "$post_resume_next_break_segmented" != "__none__" ]; then
    controller_args+=(
        --post-resume-next-break-segmented "$post_resume_next_break_segmented"
        --post-resume-next-break-hit-count "$post_resume_next_break_hit_count"
    )
fi
if [ "$call_near" != "__none__" ]; then
    controller_args+=(--call-near "$call_near")
fi
if [ "$call_near_break_linear" != "__none__" ]; then
    controller_args+=(--call-near-break-linear "$call_near_break_linear")
fi
if [ "$call_near_break_segmented" != "__none__" ]; then
    controller_args+=(--call-near-break-segmented "$call_near_break_segmented")
fi
if [ "$call_near_break_offset" != "__none__" ]; then
    controller_args+=(--call-near-break-offset "$call_near_break_offset")
fi
if [ "$call_near_continue_after_return" = "1" ]; then
    controller_args+=(--call-near-continue-after-return)
fi
if [ "$halt_after_poke" = "1" ]; then
    controller_args+=(--halt-after-poke)
fi
if [ "$dump_low_memory" = "1" ]; then
    controller_args+=(--dump-low-memory)
fi
if [ "$omit_checkpoint_vga" = "1" ]; then
    controller_args+=(--omit-checkpoint-vga)
fi
if [ "$checkpoint_dac" = "1" ]; then
    controller_args+=(--checkpoint-dac)
fi
if [ "$checkpoint_displaydump" = "1" ]; then
    controller_args+=(--checkpoint-displaydump)
fi
if [ "$display_sequence_frames" -gt 0 ]; then
    controller_args+=(--display-sequence-frames "$display_sequence_frames")
    controller_args+=(--display-sequence-interval "$display_sequence_interval")
fi
if [ "$post_resume_display_history_capacity" -gt 0 ]; then
    controller_args+=(
        --post-resume-display-history-capacity
        "$post_resume_display_history_capacity"
    )
fi
if [ "$checkpoint_screenshot" = "1" ]; then
    controller_args+=(--checkpoint-screenshot)
fi
for region in "${checkpoint_screenshot_preserve_memory[@]}"; do
    controller_args+=(
        --checkpoint-screenshot-preserve-memory "$region"
    )
done
if [ "$checkpoint_post_display_break_segmented" != "__none__" ]; then
    controller_args+=(
        --checkpoint-post-display-break-segmented
        "$checkpoint_post_display_break_segmented"
        --checkpoint-post-display-poke
        "$checkpoint_post_display_poke"
        --checkpoint-post-display-delay
        "$checkpoint_post_display_delay"
        --checkpoint-post-display-scope
        "$checkpoint_post_display_scope"
    )
fi
if [ "$post_resume_next_break_hit_series" != "__none__" ]; then
    controller_args+=(
        --post-resume-next-break-hit-series \
        "$post_resume_next_break_hit_series"
    )
fi
if [ "$final_post_display_break_segmented" != "__none__" ]; then
    controller_args+=(
        --final-post-display-break-segmented
        "$final_post_display_break_segmented"
        --final-post-display-poke
        "$final_post_display_poke"
        --final-post-display-delay
        "$final_post_display_delay"
    )
    if [ "$final_post_display_value" != "__none__" ]; then
        controller_args+=(
            --final-post-display-value "$final_post_display_value"
        )
    fi
fi
if [ "$resume_side_break_segmented" != "__none__" ]; then
    controller_args+=(
        --resume-side-break-segmented "$resume_side_break_segmented"
    )
    if [ "$resume_side_break_max_hits" -gt 0 ]; then
        controller_args+=(
            --state-side-break-max-hits "$resume_side_break_max_hits"
        )
    fi
    if [ "$resume_side_break_start_value" -gt 0 ]; then
        controller_args+=(
            --state-side-break-start-value "$resume_side_break_start_value"
        )
    fi
fi
if [ "$checkpoint_save_state" = "1" ]; then
    controller_args+=(--checkpoint-save-state)
fi
    if [ "$checkpoint_save_state_first" = "1" ]; then
    controller_args+=(--checkpoint-save-state-first)
fi
if [ "$state_input_stop_value" != "__none__" ]; then
    controller_args+=(--state-input-stop-value "$state_input_stop_value")
fi
if [ "$load_save_state" != "__none__" ]; then
    controller_args+=(--load-save-state "$load_save_state")
fi
if [ "$load_save_state_continue" = "1" ]; then
    controller_args+=(--load-save-state-continue)
fi
if [ "$load_save_state_paused" = "1" ]; then
    controller_args+=(--load-save-state-paused)
fi
if [ "$load_save_state_ready_screen" != "__none__" ]; then
    controller_args+=(
        --load-save-state-ready-screen "$load_save_state_ready_screen"
        --load-save-state-ready-timeout "$load_save_state_ready_timeout"
    )
fi
if [ "$screenshot" = "1" ]; then
    controller_args+=(--screenshot)
fi

PYTHONPATH="$toolkit/src" python3 -u -m dos_re_harness.remote_capture "${controller_args[@]}"

PYTHONPATH="$toolkit/src" python3 -m dos_re_harness.cli parse-state \
    --schema "$state_schema" \
    --dump "$out_dir/remote_runtime_ds.bin" \
    --base 0 \
    --out "$out_dir/remote_runtime_ds.json"

echo "DOSBox-X PID: $pid"
echo "Log: $log"
if [ "$keep" = "1" ]; then
    echo "Left running because -KeepRunning was set."
fi
'@

$tempScript = Join-Path $env:TEMP ("dos_re_runtime_{0}.sh" -f ([Guid]::NewGuid().ToString("N")))
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$bash = $bash.Replace("`r`n", "`n").Replace("`r", "`n")
[System.IO.File]::WriteAllText($tempScript, $bash, $utf8NoBom)
try {
    $tempScriptWsl = Convert-WindowsPathToWsl $tempScript
    $restoreRegistersWsl = "__none__"
    if ($RestoreRegisters.Trim().Length -gt 0) {
        $restoreRegistersWsl = Convert-WindowsPathToWsl (Resolve-Path $RestoreRegisters).Path
    }
    $callNearArg = if ($CallNear.Trim().Length -gt 0) { $CallNear } else { "__none__" }
    $programArgumentsArg = if ($ProgramArguments.Length -gt 0) {
        $ProgramArguments
    } else {
        "__none__"
    }
    $vgaSequenceStopSha256Arg = if ($VgaSequenceStopSha256.Trim().Length -gt 0) {
        $VgaSequenceStopSha256.ToLowerInvariant()
    } else {
        "__none__"
    }
    $breakpointLinearArg = if ($BreakpointLinear.Trim().Length -gt 0) {
        $BreakpointLinear
    } else {
        "__none__"
    }
    $inputScriptWsl = if ($InputScript.Trim().Length -gt 0) {
        $resolvedInputScript = Resolve-WorkspacePath $repoRoot $InputScript
        Convert-WindowsPathToWsl $resolvedInputScript
    } else {
        "__none__"
    }
    $resumeCheckpointScriptArg = if (
        $ResumeCheckpointScript.Trim().Length -gt 0
    ) {
        $ResumeCheckpointScript
    } else {
        "__none__"
    }
    $resumeNextLinearArg = if ($ResumeNextLinear.Trim().Length -gt 0) {
        $ResumeNextLinear
    } else {
        "__none__"
    }
    $resumeSideBreakSegmentedArg = if (
        $ResumeSideBreakSegmented.Trim().Length -gt 0
    ) {
        $ResumeSideBreakSegmented
    } else {
        "__none__"
    }
    $oplLogPathArg = if ($OplLogPath.Trim().Length -gt 0) {
        Convert-WindowsPathToWsl (
            Resolve-WorkspacePath $repoRoot $OplLogPath -AllowMissing
        )
    } else {
        "__none__"
    }
    $oplTickLinearArg = if ($OplTickLinear.Trim().Length -gt 0) {
        $OplTickLinear
    } else {
        "__none__"
    }
    $backendInputScriptWsl = if ($BackendInputScript.Trim().Length -gt 0) {
        $resolvedBackendInputScript = Resolve-WorkspacePath `
            $repoRoot $BackendInputScript
        Convert-WindowsPathToWsl $resolvedBackendInputScript
    } else {
        "__same__"
    }
    $oplTickDsOffsetArg = if ($OplTickDsOffset.Trim().Length -gt 0) {
        $OplTickDsOffset
    } else {
        "__none__"
    }
    $stateInputDynamicRequested = (
        $StateInputHookOffset.Trim().Length -gt 0 -or
        $StateInputDsOffset.Trim().Length -gt 0 -or
        $StateInputHookOffsetAlt.Trim().Length -gt 0
    )
    $stateInputStopRequested = $StateInputStopValue.Trim().Length -gt 0
    if (
        ($StateInputHookOffset.Trim().Length -gt 0) -ne
        ($StateInputDsOffset.Trim().Length -gt 0)
    ) {
        throw "StateInputHookOffset and StateInputDsOffset must be supplied together"
    }
    if ($stateInputDynamicRequested -and (
        $StateInputHookLinear.Trim().Length -gt 0 -or
        $StateInputLinear.Trim().Length -gt 0
    )) {
        throw "Dynamic state-input offsets cannot be combined with linear addresses"
    }
    if (
        $stateInputDynamicRequested -and
        $InputScript.Trim().Length -eq 0 -and
        -not $stateInputStopRequested
    ) {
        throw "Dynamic state-input offsets require InputScript or StateInputStopValue"
    }
    if (
        $StateInputHookOffsetAlt.Trim().Length -gt 0 -and
        $StateInputHookOffset.Trim().Length -eq 0
    ) {
        throw "StateInputHookOffsetAlt requires StateInputHookOffset"
    }
    $stateInputHookLinearArg = if (
        $StateInputHookLinear.Trim().Length -gt 0
    ) {
        if (
            $InputScript.Trim().Length -eq 0 -and
            -not $stateInputStopRequested
        ) {
            throw "StateInputHookLinear requires InputScript or StateInputStopValue"
        }
        if ($StateInputLinear.Trim().Length -eq 0) {
            throw "StateInputHookLinear requires StateInputLinear"
        }
        $StateInputHookLinear
    } else {
        if ($StateInputLinear.Trim().Length -gt 0) {
            throw "StateInputLinear requires StateInputHookLinear"
        }
        if ($StateInputLogPath.Trim().Length -gt 0 -and -not $stateInputDynamicRequested) {
            throw "StateInputLogPath requires StateInputHookLinear"
        }
        "__none__"
    }
    $stateInputLinearArg = if ($StateInputLinear.Trim().Length -gt 0) {
        $StateInputLinear
    } else {
        "__none__"
    }
    $stateInputLogPathWsl = if (
        $StateInputLogPath.Trim().Length -gt 0
    ) {
        Convert-WindowsPathToWsl (
            Resolve-WorkspacePath $repoRoot $StateInputLogPath -AllowMissing
        )
    } else {
        "__none__"
    }
    $postResumeBreakLinearArg = if (
        $PostResumeBreakLinear.Trim().Length -gt 0
    ) {
        $PostResumeBreakLinear
    } else {
        "__none__"
    }
    $postResumeBreakSegmentedArg = if (
        $PostResumeBreakSegmented.Trim().Length -gt 0
    ) {
        $PostResumeBreakSegmented
    } else {
        "__none__"
    }
    $postResumeBreakHitSeriesArg = if (
        $PostResumeBreakHitSeries.Trim().Length -gt 0
    ) {
        $PostResumeBreakHitSeries
    } else {
        "__none__"
    }
    $postResumeNextBreakLinearArg = if (
        $PostResumeNextBreakLinear.Trim().Length -gt 0
    ) {
        $PostResumeNextBreakLinear
    } else {
        "__none__"
    }
    $postResumeNextBreakSegmentedArg = if (
        $PostResumeNextBreakSegmented.Trim().Length -gt 0
    ) {
        $PostResumeNextBreakSegmented
    } else {
        "__none__"
    }
    $pokeFilesWsl = @(
        foreach ($spec in $PokeFile) {
            Convert-PokeFileSpecToWsl $spec
        }
    )
    $postResumePokeFilesWsl = @(
        foreach ($spec in $PostResumePokeFile) {
            Convert-PokeFileSpecToWsl $spec
        }
    )
    $postResumeContinueAfterPokeArg = if (
        $PostResumeContinueAfterPoke
    ) { "1" } else { "0" }
    $callNearContinueAfterReturnArg = if (
        $CallNearContinueAfterReturn
    ) { "1" } else { "0" }
    $turboArg = if ($Turbo) { "true" } else { "false" }
    $loadSaveStateWsl = if ($LoadSaveState.Trim().Length -gt 0) {
        Convert-WindowsPathToWsl (
            Resolve-WorkspacePath $repoRoot $LoadSaveState
        )
    } else {
        "__none__"
    }
    $loadSaveStateReadyScreenArg = if (
        $LoadSaveStateReadyScreen.Trim().Length -gt 0
    ) {
        $LoadSaveStateReadyScreen
    } else {
        "__none__"
    }
    # Keep the legacy $captureVideoArg @StartupKey ordering contract visible.
    # The fixed positional prefix remains available to wrappers that inspect
    # this launcher text; waitStateBreakLinearArg extends it before variadic
    # startup keys.
    # Legacy textual prefix: $oplLogPathArg $oplTickLinearArg $callNearContinueAfterReturnArg $RemoteTimeout $vgaSequenceScreenshotOnStopArg $stateInputHookLinearArg $stateInputLinearArg $StateInputWidth $stateInputLogPathWsl $turboArg $CheckpointPostDisplayScope $stateInputStopValueArg $GdbPort $QmpPort @StartupKey
    $stateInputStopValueArg = if ($StateInputStopValue.Trim().Length -gt 0) {
        $StateInputStopValue
    } else {
        "__none__"
    }
    $checkpointDacArg = if ($CheckpointDac) { "1" } else { "0" }
    $waitStateBreakLinearArg = $checkpointDacArg
    if (
        $stateInputStopRequested -and
        $StateInputHookLinear.Trim().Length -eq 0 -and
        -not $stateInputDynamicRequested
    ) {
        throw "StateInputStopValue requires a state-input hook and state address"
    }
    $stateInputHookOffsetArg = if (
        $StateInputHookOffset.Trim().Length -gt 0
    ) {
        $StateInputHookOffset
    } else {
        "__none__"
    }
    $stateInputDsOffsetArg = if (
        $StateInputDsOffset.Trim().Length -gt 0
    ) {
        $StateInputDsOffset
    } else {
        "__none__"
    }
    $backendRuntimeArgs = @()
    if ($backendInputScriptWsl -ne "__same__") {
        $backendRuntimeArgs += @(
            "--backend-input-script", $backendInputScriptWsl
        )
    }
    if ($StateInputObserveOnly) {
        $backendRuntimeArgs += "--state-input-observe-only"
    }
    if ($VgaSequenceScreenshotAll) {
        $backendRuntimeArgs += "--vga-sequence-screenshot-all"
    }
    if ($CallNearBreakLinear.Trim().Length -gt 0) {
        $backendRuntimeArgs += @(
            "--call-near-break-linear",
            $CallNearBreakLinear
        )
    }
    if ($CallNearBreakSegmented.Trim().Length -gt 0) {
        $backendRuntimeArgs += @(
            "--call-near-break-segmented",
            $CallNearBreakSegmented
        )
    }
    if ($CallNearBreakOffset.Trim().Length -gt 0) {
        $backendRuntimeArgs += @(
            "--call-near-break-offset",
            $CallNearBreakOffset
        )
    }
    if ($LoadSaveStateContinue) {
        $backendRuntimeArgs += "--load-save-state-continue"
    }
    if ($LoadSaveStatePaused) {
        $backendRuntimeArgs += "--load-save-state-paused"
    }
    if ($CheckpointSaveStateFirst) {
        $backendRuntimeArgs += "--checkpoint-save-state-first"
    }
    if ($CheckpointDisplayDump) {
        $backendRuntimeArgs += "--checkpoint-displaydump"
    }
    if ($DisplaySequenceFrames -gt 0) {
        $backendRuntimeArgs += @(
            "--display-sequence-frames", $DisplaySequenceFrames,
            "--display-sequence-interval", $DisplaySequenceInterval
        )
    }
    if ($PostResumeDisplayHistoryCapacity -gt 0) {
        $backendRuntimeArgs += @(
            "--post-resume-display-history-capacity",
            $PostResumeDisplayHistoryCapacity
        )
    }
    foreach ($region in $CheckpointScreenshotPreserveMemory) {
        $backendRuntimeArgs += @(
            "--checkpoint-screenshot-preserve-memory",
            $region
        )
    }
    if ($PostResumeNextBreakHitSeries.Trim().Length -gt 0) {
        $backendRuntimeArgs += @(
            "--post-resume-next-break-hit-series",
            $PostResumeNextBreakHitSeries
        )
    }
    if ($PostResumeContinue) {
        $backendRuntimeArgs += "--post-resume-continue"
    }
    if ($OplTickDsOffset.Trim().Length -gt 0) {
        $backendRuntimeArgs += @("--opl-tick-ds-offset", $OplTickDsOffset)
    }
    if ($StateInputHookOffset.Trim().Length -gt 0) {
        $backendRuntimeArgs += @(
            "--state-input-hook-offset", $StateInputHookOffset,
            "--state-input-ds-offset", $StateInputDsOffset
        )
    }
    if ($StateInputHookOffsetAlt.Trim().Length -gt 0) {
        $backendRuntimeArgs += @(
            "--state-input-hook-offset-alt", $StateInputHookOffsetAlt
        )
    }
    if ($StateInputTracePath.Trim().Length -gt 0) {
        $tracePathWsl = Convert-WindowsPathToWsl (
            Resolve-WorkspacePath $repoRoot $StateInputTracePath -AllowMissing
        )
        $backendRuntimeArgs += @(
            "--state-input-trace", $tracePathWsl
        )
    }
    if ($StateInputWriteOffset.Trim().Length -gt 0) {
        $backendRuntimeArgs += @(
            "--state-input-write-offset", $StateInputWriteOffset
        )
    }
    if ($StateInputWriteLinear.Trim().Length -gt 0) {
        $backendRuntimeArgs += @(
            "--state-input-write-linear", $StateInputWriteLinear
        )
    }
    if ($StateInputWriteValue.Trim().Length -gt 0) {
        $backendRuntimeArgs += @(
            "--state-input-write-value", $StateInputWriteValue,
            "--state-input-write-width", $StateInputWriteWidth
        )
    }
    $variadicControllerArgs = @()
    if ($StartupKey.Count -gt 0) {
        # The generated WSL wrapper treats unmarked variadic arguments as
        # startup actions.  Do not pass the controller option marker through
        # that wrapper; it would be re-emitted as a startup action and could
        # leave remote_capture with a dangling --startup-key.
        $variadicControllerArgs += $StartupKey
    }
    if ($Poke.Count -gt 0) {
        $variadicControllerArgs += "--pokes"
        $variadicControllerArgs += $Poke
    }
    if ($pokeFilesWsl.Count -gt 0) {
        $variadicControllerArgs += "--poke-files"
        $variadicControllerArgs += $pokeFilesWsl
    }
    if ($PostRestoreKey.Count -gt 0) {
        $variadicControllerArgs += "--post-restore"
        $variadicControllerArgs += $PostRestoreKey
    }
    if ($WaitState.Count -gt 0) {
        $variadicControllerArgs += "--wait-state"
        $variadicControllerArgs += $WaitState
    }
    if ($PostWaitKey.Count -gt 0) {
        $variadicControllerArgs += "--post-wait-key"
        $variadicControllerArgs += $PostWaitKey
    }
    if ($PostResumePoke.Count -gt 0) {
        $variadicControllerArgs += "--post-resume-pokes"
        $variadicControllerArgs += $PostResumePoke
    }
    if ($postResumePokeFilesWsl.Count -gt 0) {
        $variadicControllerArgs += "--post-resume-poke-files"
        $variadicControllerArgs += $postResumePokeFilesWsl
    }
    if ($ResumeSideBreakPoke.Count -gt 0) {
        $variadicControllerArgs += "--state-side-break-pokes"
        $variadicControllerArgs += $ResumeSideBreakPoke
    }
    if ($finalPostDisplayBreakSegmentedArg -ne "__none__") {
        $variadicControllerArgs += @(
            "--final-post-display",
            $finalPostDisplayBreakSegmentedArg,
            $finalPostDisplayPokeArg,
            $FinalPostDisplayDelay,
            $stateInputStopValueArg
        )
    }
    & wsl.exe --exec bash $tempScriptWsl $repoRootWsl $outPathWsl $Program $mountPathWsl $DelaySeconds $StartupDelaySeconds $DumpSize $DumpSegment $keep $screenshotArg $WaitStateTimeout $WaitStateInterval $restoreRegistersWsl $haltAfterPokeArg $dumpLowMemoryArg $callNearArg $VgaSequenceFrames $VgaSequenceInterval $vgaSequenceStopSha256Arg $captureAudioArg $captureSfxOnlyArg $stateSchemaWsl $screenSignaturesWsl $toolkitRootWsl $dosboxBinaryWsl $RuntimeName $Machine $CpuType $Cycles $programArgumentsArg $VgaAddress $VgaWidth $VgaHeight $breakpointLinearArg $inputScriptWsl $resumeCheckpointScriptArg $resumeNextLinearArg $omitCheckpointVgaArg $checkpointScreenshotArg $postResumeBreakLinearArg $PostResumeBreakHitCount $postResumeBreakSegmentedArg $postResumeNextBreakLinearArg $PostResumeNextBreakHitCount $postResumeNextBreakSegmentedArg $postResumeBreakHitSeriesArg $postResumeContinueAfterPokeArg $checkpointSaveStateArg $loadSaveStateWsl $loadSaveStateReadyScreenArg $LoadSaveStateReadyTimeout $captureVideoArg $checkpointPostDisplayBreakSegmentedArg $checkpointPostDisplayPokeArg $CheckpointPostDisplayDelay $resumeSideBreakSegmentedArg $ResumeSideBreakMaxHits $ResumeSideBreakStartValue $oplLogPathArg $oplTickLinearArg $callNearContinueAfterReturnArg $RemoteTimeout $vgaSequenceScreenshotOnStopArg $stateInputHookLinearArg $stateInputLinearArg $StateInputWidth $stateInputLogPathWsl $turboArg $CheckpointPostDisplayScope $stateInputStopValueArg $GdbPort $QmpPort $waitStateBreakLinearArg @variadicControllerArgs @backendRuntimeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "wsl.exe failed with exit code $LASTEXITCODE"
    }
}
finally {
    Remove-Item -LiteralPath $tempScript -Force -ErrorAction SilentlyContinue
}
