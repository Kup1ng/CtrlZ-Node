#!/bin/sh
# Pulls Ctrl Z Panel/shared into this repository's shared/ and proves the copies
# match. The tool runs from the canonical (Panel) copy, so it is never replaced
# while it runs. No logic here.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
panel="$here/../Ctrl Z Panel/shared"
exec go -C "$panel" run ./cmd/sharedtool sync --from "$panel" --to "$here/shared" "$@"
