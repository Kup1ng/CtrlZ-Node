# Verifies this copy of shared against its CHECKSUMS, and against the Panel copy
# when the two repositories sit side by side. No logic here.
$ErrorActionPreference = 'Stop'
$here = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$panel = Join-Path (Split-Path $here -Parent) 'Ctrl Z Panel\shared'
if (Test-Path $panel) {
    & go -C $panel run ./cmd/sharedtool verify $panel (Join-Path $here 'shared')
} else {
    & go -C (Join-Path $here 'shared') run ./cmd/sharedtool verify (Join-Path $here 'shared')
}
exit $LASTEXITCODE
