#!/bin/sh
# The job "unbound": T-031's injection test against a real Unbound (p4-nodes 7.7 and 11.5). No other
# job has an Unbound, so the test is behind the build tag unboundlab and runs here only. The package
# comes from the runner's own Ubuntu 24.04 archive (what the node's bundle carries too, p4-nodes 7.1);
# the version it gets is printed first, so a run says which Unbound it judged. The rest is
# scripts/unbound-lab.sh of the repository, which scripts/conformance.sh runs as well.
set -eu
here=$(cd "$(dirname "$0")/../.." && pwd)
"$here/scripts/go-pin-check.sh"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends unbound
dpkg-query -W -f='unbound package: ${Package} ${Version}\n' unbound
unbound -V | head -n 1
sh "$here/scripts/unbound-lab.sh"
