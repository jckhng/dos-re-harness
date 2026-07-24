$ErrorActionPreference = "Stop"
$toolkitRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$env:PYTHONPATH = Join-Path $toolkitRoot "src"
& python -m unittest discover -s (Join-Path $toolkitRoot "tests") -v
exit $LASTEXITCODE
