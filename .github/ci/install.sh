#!/bin/sh
# The job "install": TestInstallInContainer really runs. It installs the node, and upgrades it, in a clean
# ubuntu:24.04 container with no network (p4-nodes 11.5, N7 and N11), one container per scenario. The other jobs skip
# it (by design: no Docker switch). Here the switch is on and a skip is the job's failure: shardrun
# turns its expected-skip rule for that test off while CTRLZ_INSTALL_TEST is 1, so a runner without
# Docker, or a test that skips for any reason, fails the job and cannot go green by skipping.
#
# The image is the one the install targets, by the digest that was read when the test was written
# (Plan.md, W5c), pulled by digest and then given the tag the test looks for, so what the scenarios
# run on is those bytes and not whatever the tag points to today. The test uses the tag on purpose
# (a refreshed image is a visible change of a run); this script makes the tag mean the digest.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
digest=sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289
"$here/scripts/go-pin-check.sh"
docker version >/dev/null
docker pull "ubuntu@$digest"
docker tag "ubuntu@$digest" ubuntu:24.04
want=$(docker image inspect --format '{{.Id}}' "ubuntu@$digest")
have=$(docker image inspect --format '{{.Id}}' ubuntu:24.04)
[ -n "$want" ] && [ "$want" = "$have" ] || { echo "install: ubuntu:24.04 is not the image of the pinned digest ($want, $have)" >&2; exit 1; }
cd "$here"
export CTRLZ_INSTALL_TEST=1
# timeout_minutes is the job's bound; shardrun stops go test five minutes before it.
SHARD_JSON='{"id":"install","kind":"packages","packages":["./internal/installtest"],"timeout_minutes":45}' go run ./.github/ci/shardrun tests
echo "install: ok"
