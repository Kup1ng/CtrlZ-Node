#!/bin/sh
# Installs gitleaks and govulncheck at the exact versions of the development machine.
# Run from anywhere; `go install pkg@version` is done from a temp directory so that it
# never reads the module of the checkout.
set -eu
GITLEAKS_VERSION=v8.30.1
GOVULNCHECK_VERSION=v1.9.0
cd "${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
go install "github.com/zricethezav/gitleaks/v8@$GITLEAKS_VERSION"
go install "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION"
# A later step of the same job finds the tools without a path of its own.
[ -z "${GITHUB_PATH:-}" ] || echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"
echo "install-tools: ok"
