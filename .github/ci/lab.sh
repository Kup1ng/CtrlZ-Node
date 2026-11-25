#!/bin/sh
# The job "tests (lab)": the whole module and shared/ built with the tag ctrlz_lab, the build the P4
# fault tests run on a private network. The release jobs (static, tests) never build a file with that
# tag, so without this job the lab-tagged test files (cmd/ctrlz-bundle/sign_lab_test.go,
# shared/netclass/lab_test.go) and the lab cases of the golden vectors (ptv-050, ptv-052, ptv-053)
# would run in no job, and the release-only tests would stay unjudged in the other direction (they
# skip here, by design, and run in `tests`). gofiles.sh knows the tag set from its own table and
# refuses a job whose GOFLAGS names another one; shardrun reads the same GOFLAGS from go and accepts
# the lab-build skips only in this job. The job fails like the release ones on any other skip, on a
# package that reports nothing and on a declared test with no result.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
"$here/scripts/go-pin-check.sh"
# Exported for every go command below, shardrun's own go run included: the helper has no build tag
# of its own, so it compiles the same.
export GOFLAGS=-tags=ctrlz_lab
sh "$here/.github/ci/gofiles.sh" "$here" "$here"
sh "$here/.github/ci/gofiles.sh" "$here/shared" "$here"
cd "$here"
go run ./.github/ci/shardrun module shared
go run ./.github/ci/shardrun module .
echo "lab: ok"
