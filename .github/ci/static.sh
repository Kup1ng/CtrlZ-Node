#!/bin/sh
# The static half of scripts/ci.sh of the Node: everything but the tests and the scanners,
# which have their own jobs. Same checks, same messages. It is a copy of that part of
# ci.sh, so a change there must be made here too.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)

# The host compiler must be the one go.mod pins, before anything is judged with it.
"$here/scripts/go-pin-check.sh"
# One copy of shared is here; the equality with the Panel's copy is checked by the local run.
"$here/scripts/shared-verify.sh"
# A test file that go leaves out on this runner (a _windows_test.go name, a build tag) is run by
# no job below, and the run would stay green: refuse it (CI review round 6, ci-r6-1).
sh "$here/.github/ci/gofiles.sh" "$here" "$here"
sh "$here/.github/ci/gofiles.sh" "$here/shared" "$here"
# Not a bare `go test`: shardrun reads the -json result, so a skip is judged. The linear-time
# guard of shared/quarantine skips when the host is too noisy to measure it; that guard is
# what keeps a hostile config entry from costing a node quadratic time, so shardrun repeats
# it and fails the job if it never measures, and only the regeneration switches may skip.
(cd "$here" && go run ./.github/ci/shardrun module shared)

cd "$here"
test -z "$(gofmt -l cmd internal)" || { echo "gofmt: run gofmt -w"; gofmt -l cmd internal; exit 1; }
go build ./...
# The node only ever runs on Ubuntu, and development is on Windows. The runner is Ubuntu,
# so the plain vet is the linux one.
go vet ./...
GOOS=windows go vet ./...
echo "static: ok"
