# Pulls Ctrl Z Panel/shared into this repository's shared/ and proves the copies
# match. The tool runs from the canonical (Panel) copy. No logic here.
$ErrorActionPreference = 'Stop'
$here = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$panel = Join-Path (Split-Path $here -Parent) 'Ctrl Z Panel\shared'
& go -C $panel run ./cmd/sharedtool sync --from $panel --to (Join-Path $here 'shared') @args
exit $LASTEXITCODE
