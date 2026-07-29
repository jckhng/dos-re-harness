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
    [double]$DelaySeconds = 4.0,
    [double]$StartupDelaySeconds = 3.0,
    [string]$StartupSequence = "",
    [string]$InputScript = "",
    [string[]]$StartupKey = @(),
    [string[]]$Poke = @(),
    [string[]]$PokeFile = @(),
    [string]$RestoreRegisters = "",
    [string]$ResumeCheckpointScript = "",
    [string]$ResumeNextLinear = "",
    [string]$PostResumeBreakLinear = "",
    [string]$PostResumeBreakSegmented = "",
    [int]$PostResumeBreakHitCount = 1,
    [string]$PostResumeBreakHitSeries = "",
    [string[]]$PostResumePokeFile = @(),
    [string]$PostResumeNextBreakLinear = "",
    [string]$PostResumeNextBreakSegmented = "",
    [int]$PostResumeNextBreakHitCount = 1,
    [string]$CallNear = "",
    [string]$BreakpointLinear = "",
    [switch]$HaltAfterPoke,
    [string]$PostRestoreSequence = "",
    [string[]]$PostRestoreKey = @(),
    [string[]]$WaitState = @(),
    [double]$WaitStateTimeout = 30.0,
    [double]$WaitStateInterval = 0.05,
    [int]$VgaSequenceFrames = 0,
    [double]$VgaSequenceInterval = (1.0 / 70.0),
    [string]$VgaSequenceStopSha256 = "",
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
    [switch]$CheckpointScreenshot,
    [switch]$CaptureAudio,
    [switch]$CaptureSfxOnly,
    [Parameter(Mandatory = $true)]
    [string]$StateSchema,
    [Parameter(Mandatory = $true)]
    [string]$ScreenSignatures,
    [string]$WorkspaceRoot = "",
    [Parameter(Mandatory = $true)]
    [string]$DosboxBinary,
    [ValidatePattern("^[A-Za-z0-9_.-]+$")]
    [string]$RuntimeName = "dos_re_runtime",
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
$captureAudioArg = if ($CaptureAudio -or $CaptureSfxOnly) { "1" } else { "0" }
$captureSfxOnlyArg = if ($CaptureSfxOnly) { "1" } else { "0" }
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
shift 46
if [ "$program_arguments" = "__none__" ]; then
    program_arguments=""
fi
startup_keys=()
poke_specs=()
poke_file_specs=()
post_restore_keys=()
wait_state_specs=()
post_resume_poke_file_specs=()
parsing_pokes=0
parsing_poke_files=0
parsing_post_restore=0
parsing_wait_state=0
parsing_post_resume_poke_files=0
for arg in "$@"; do
    if [ "$arg" = "--" ] || [ "$arg" = "--pokes" ]; then
        parsing_pokes=1
        parsing_poke_files=0
        parsing_post_restore=0
        parsing_wait_state=0
        parsing_post_resume_poke_files=0
        continue
    fi
    if [ "$arg" = "--poke-files" ]; then
        parsing_pokes=0
        parsing_poke_files=1
        parsing_post_restore=0
        parsing_wait_state=0
        parsing_post_resume_poke_files=0
        continue
    fi
    if [ "$arg" = "--post-restore" ]; then
        parsing_pokes=0
        parsing_poke_files=0
        parsing_post_restore=1
        parsing_wait_state=0
        parsing_post_resume_poke_files=0
        continue
    fi
    if [ "$arg" = "--wait-state" ]; then
        parsing_pokes=0
        parsing_poke_files=0
        parsing_post_restore=0
        parsing_wait_state=1
        parsing_post_resume_poke_files=0
        continue
    fi
    if [ "$arg" = "--post-resume-poke-files" ]; then
        parsing_pokes=0
        parsing_poke_files=0
        parsing_post_restore=0
        parsing_wait_state=0
        parsing_post_resume_poke_files=1
        continue
    fi
    if [ "$parsing_post_resume_poke_files" = "1" ]; then
        post_resume_poke_file_specs+=("$arg")
    elif [ "$parsing_wait_state" = "1" ]; then
        wait_state_specs+=("$arg")
    elif [ "$parsing_post_restore" = "1" ]; then
        post_restore_keys+=("$arg")
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
qmpserver = true
captures = $out_dir

[cpu]
cputype = $cpu_type
core = normal
cycles = $cycles

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
$program $program_arguments
EOF

nohup env SDL_VIDEODRIVER=dummy SDL_AUDIODRIVER=dummy "$dosbox" -conf "$conf" >"$log" 2>&1 &
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
    --out-dir "$out_dir"
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
if [ "$restore_registers" != "__none__" ]; then
    controller_args+=(--restore-registers "$restore_registers")
fi
if [ "$resume_checkpoint_script" != "__none__" ]; then
    controller_args+=(--resume-checkpoint-script "$resume_checkpoint_script")
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
for poke_file in "${post_resume_poke_file_specs[@]}"; do
    controller_args+=(--post-resume-poke-file "$poke_file")
done
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
if [ "$halt_after_poke" = "1" ]; then
    controller_args+=(--halt-after-poke)
fi
if [ "$dump_low_memory" = "1" ]; then
    controller_args+=(--dump-low-memory)
fi
if [ "$omit_checkpoint_vga" = "1" ]; then
    controller_args+=(--omit-checkpoint-vga)
fi
if [ "$checkpoint_screenshot" = "1" ]; then
    controller_args+=(--checkpoint-screenshot)
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
    & wsl.exe --exec bash $tempScriptWsl $repoRootWsl $outPathWsl $Program $mountPathWsl $DelaySeconds $StartupDelaySeconds $DumpSize $DumpSegment $keep $screenshotArg $WaitStateTimeout $WaitStateInterval $restoreRegistersWsl $haltAfterPokeArg $dumpLowMemoryArg $callNearArg $VgaSequenceFrames $VgaSequenceInterval $vgaSequenceStopSha256Arg $captureAudioArg $captureSfxOnlyArg $stateSchemaWsl $screenSignaturesWsl $toolkitRootWsl $dosboxBinaryWsl $RuntimeName $Machine $CpuType $Cycles $programArgumentsArg $VgaAddress $VgaWidth $VgaHeight $breakpointLinearArg $inputScriptWsl $resumeCheckpointScriptArg $resumeNextLinearArg $omitCheckpointVgaArg $checkpointScreenshotArg $postResumeBreakLinearArg $PostResumeBreakHitCount $postResumeBreakSegmentedArg $postResumeNextBreakLinearArg $PostResumeNextBreakHitCount $postResumeNextBreakSegmentedArg $postResumeBreakHitSeriesArg @StartupKey --pokes @Poke --poke-files @pokeFilesWsl --post-restore @PostRestoreKey --wait-state @WaitState --post-resume-poke-files @postResumePokeFilesWsl
    if ($LASTEXITCODE -ne 0) {
        throw "wsl.exe failed with exit code $LASTEXITCODE"
    }
}
finally {
    Remove-Item -LiteralPath $tempScript -Force -ErrorAction SilentlyContinue
}
