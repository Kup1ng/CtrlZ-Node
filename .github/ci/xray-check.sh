#!/bin/sh
# The job "xray start check" (docs/specs/p4b-proxy.md 17, package B0; Plan.md D69): the pinned Xray-core release is fetched,
# checked against its pinned SHA-256 and run through the experiments of .github/ci/xraycheck, next to the source of the same tag
# from the Go module proxy (checked against its pinned module hash). It runs only for branches named ci/p4b-b0*, so no other
# run fetches anything from outside GitHub's own infrastructure, and it judges nothing: the program prints one RESULT line per
# claim of the spec, and a person writes docs/research/xray-start-check.md from the log. A bump of the release is a new pin
# here, a new run, and a new copy of that document.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
"$here/scripts/go-pin-check.sh"

tag=v26.11.9
asset=Xray-linux-64.zip
# The SHA-256 of the archive: the value GitHub shows for the asset of the release (read 2026-11-25 with the API) and the one
# in the release's own .dgst file, which is fetched and compared below.
zip_sha256=b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82
# The module of the same tag on the Go module proxy: the commit the tag points to and the hash go.sum would record.
src_commit=676eaf66f8f05d4d558ee7a74b4736623d3feeb9
src_sum='h1:p2uoadP+ulClbJ9dn+QioF2SfBqRly6VoKJosHqwcRo='

work=$(mktemp -d)
base="https://github.com/XTLS/Xray-core/releases/download/$tag"
curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$work/$asset" "$base/$asset"
curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$work/$asset.dgst" "$base/$asset.dgst"
echo "xray-check: fetched $asset ($(wc -c <"$work/$asset") bytes) and its .dgst"
echo "$zip_sha256  $work/$asset" | sha256sum -c -
if ! grep -qi "$zip_sha256" "$work/$asset.dgst"; then
  echo "xray-check: the release's .dgst file does not carry the pinned SHA-256; it says:" >&2
  cat "$work/$asset.dgst" >&2
  exit 1
fi
echo "xray-check: the pinned SHA-256 matches the archive and the release's .dgst file"

cd "$work"
GOFLAGS= go mod download -json "github.com/xtls/xray-core@$src_commit" >"$work/mod.json"
dir=$(sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p' "$work/mod.json")
sum=$(sed -n 's/^[[:space:]]*"Sum": "\(.*\)",$/\1/p' "$work/mod.json")
if [ -z "$dir" ] || [ "$sum" != "$src_sum" ]; then
  echo "xray-check: the module source is not the pinned one (dir '$dir', sum '$sum')" >&2
  cat "$work/mod.json" >&2
  exit 1
fi
echo "xray-check: module source of $tag is $dir with the pinned hash"

cd "$here"
go run ./.github/ci/xraycheck -zip "$work/$asset" -extract "$work/bin/xray" -xray "$work/bin/xray" -src "$dir" -work "$work/run"
echo "xray-check: done"
