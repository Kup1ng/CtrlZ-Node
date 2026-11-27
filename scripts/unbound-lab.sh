#!/bin/sh
# T-031's injection test (internal/agent/unbound, build tag unboundlab) against a real Unbound:
# the two rendered configurations of the node, a hostile root in the lab, and no private or
# injected address may reach a client. Used by the job "unbound" of the GitHub workflow and by
# scripts/conformance.sh.
#
# Needs: an installed unbound, and root or passwordless sudo for two host changes the test cannot
# make itself. Unbound will not query a non-public address (that is the point of its
# do-not-query-address list), so the lab root cannot be on loopback: it takes a public-class
# address added to lo, and it answers on port 53, which an unprivileged user may not bind until
# net.ipv4.ip_unprivileged_port_start is lowered. Both are undone on exit when this script made them.
#
# A skip is a failure: the verdict is read from the test's own output, so a test that skipped,
# or never ran, cannot read as green.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"
addr=11.0.0.53

as_root() {
  if [ "$(id -u)" = 0 ]; then "$@"; else sudo -n "$@"; fi
}

if ! command -v unbound >/dev/null 2>&1 && [ ! -x /usr/sbin/unbound ]; then
  echo "unbound-lab: no unbound binary (apt-get install unbound)" >&2
  exit 1
fi

added=0
oldport=$(sysctl -n net.ipv4.ip_unprivileged_port_start)
out=$(mktemp)
cleanup() {
  rm -f "$out"
  [ "$added" = 1 ] && as_root ip addr del "$addr/32" dev lo || true
  as_root sysctl -qw "net.ipv4.ip_unprivileged_port_start=$oldport" || true
}
trap cleanup EXIT

if ! ip -4 addr show dev lo | grep -q " $addr/"; then
  as_root ip addr add "$addr/32" dev lo
  added=1
fi
as_root sysctl -qw net.ipv4.ip_unprivileged_port_start=0

status=0
go test -tags=unboundlab -run '^TestInjectionLab$' -count=1 -v -timeout 10m ./internal/agent/unbound >"$out" 2>&1 || status=$?
cat "$out"
[ "$status" = 0 ] || { echo "unbound-lab: the test failed" >&2; exit 1; }
if grep -q -e '--- SKIP' -e 'no tests to run' "$out"; then
  echo "unbound-lab: the test skipped or did not run, which is a failure" >&2
  exit 1
fi
for t in TestInjectionLab TestInjectionLab/identified TestInjectionLab/free TestInjectionLab/control_without_private-address; do
  grep -q -e "^ *--- PASS: $t " "$out" || { echo "unbound-lab: no pass reported for $t" >&2; exit 1; }
done
echo "unbound-lab: ok"
