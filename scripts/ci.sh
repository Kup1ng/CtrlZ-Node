#!/bin/sh
# Local CI for the Node repository. Fails on the first problem.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
gobin=$(go env GOPATH)/bin

# The host compiler must be the one go.mod pins, before anything is judged with it.
"$here/scripts/go-pin-check.sh"
"$here/scripts/shared-verify.sh"
go -C "$here/shared" test -count=1 ./...

cd "$here"
test -z "$(gofmt -l cmd internal)" || { echo "gofmt: run gofmt -w"; gofmt -l cmd internal; exit 1; }
go build ./...
go vet ./...
# The node only ever runs on Ubuntu, and development is on Windows.
GOOS=linux go vet ./...
go test -count=1 ./...

# Neither gate is optional: a missing tool must not read as a clean result.
"$gobin/gitleaks" git --no-banner --redact --log-level=warn "$here"
"$gobin/govulncheck" -C "$here" ./...
