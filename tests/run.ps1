# Compatibility entry point; scripts/run_tests.py owns environment and discovery.
& (Join-Path $PSScriptRoot "../scripts/run-tests.ps1") @args
exit $LASTEXITCODE
