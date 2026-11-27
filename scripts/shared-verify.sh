#!/bin/sh
# Verifies this copy of shared against its CHECKSUMS, and against the Panel copy
# when the two repositories sit side by side. No logic here.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
panel="$here/../Ctrl Z Panel/shared"
if [ -d "$panel" ]; then
  exec go -C "$panel" run ./cmd/sharedtool verify "$panel" "$here/shared"
fi
exec go -C "$here/shared" run ./cmd/sharedtool verify "$here/shared"
