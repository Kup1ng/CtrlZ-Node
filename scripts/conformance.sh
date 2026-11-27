#!/bin/sh
# The conformance suite of the Node (p4-nodes 11.4, Plan.md T-552 and D54).
#
# What it is for. A bump of a DNS transport or upstream client library (miekg/dns, quic-go, dnsproxy
# upstream, Go) that changes none of our code takes the reduced review of D54 when this suite passes.
# So the suite judges what a library can break: the listeners on every transport (DoH3 included),
# the limits registry and the listener settings walk, the query path end to end, the upstream
# clients, the telemetry queues, the injection test against a real Unbound, and the built binary's
# vulnerabilities and licences.
#
# What it is not. Spec 11.4 says "in the lab topology". Two parts need the lab VMs of T-412 and
# cannot run on one machine: the SC 8a.10 fault tests and no-egress (T-362). They are printed as
# SKIPPED with the reason, and the verdict says so: "PASS (the skipped parts did not run ...)" is the
# best one machine can give. The reduced review of D54 holds for a bump only when those two are green
# in the lab as well; until the lab exists, this script proves the non-lab half.
#
#   scripts/conformance.sh            run every step that can run here
#   scripts/conformance.sh --list     print the steps and what each runs, and run nothing
#   scripts/conformance.sh --only registry,licences    run only the named steps (a bump is judged on
#                                     the full run; --only is for debugging the suite itself)
#
# Exit status: 0 when every step that ran passed, 1 when one failed, 2 on a bad argument. A SKIPPED
# step never fails the run and is never counted as passed.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"
gobin=$(go env GOPATH)/bin
out=${CONFORMANCE_OUT:-$(mktemp -d)}
mkdir -p "$out"
bin="$out/ctrlz-node"

# name|description|command. The go test steps run whole packages on purpose: a transport library
# breaks tests nobody listed by name.
steps='build|the release binary builds|step_build
registry|L13 registry walk with DoH3, limiter and listener settings walks (N5, T-017)|step_test ./internal/dns/limits
transports|e2e of every transport, T-001 to T-004, T-548, T-549, listener behaviour|step_test ./internal/dns/listen
query-path|query path end to end, T-009, T-011, local blob answers, quarantine, nothing cached from a broken record|step_test ./internal/dns ./internal/querypath
upstreams|upstream clients and admission pinned across a dnsproxy bump, T-550 (N6)|step_test ./internal/resolve
queues|activity and counter queues bounded, drops counted, hub slow|step_test ./internal/telemetry ./internal/agent/telem
unbound|T-031 injection test with a real Unbound (needs unbound and root or sudo)|step_unbound
vuln|govulncheck on the built binary|step_vuln
licences|licence scan of the modules in the built binary|step_licences'

# Parts that need the lab topology of T-412, named so that the output is honest.
skipped='faults|SC 8a.10 fault, failback, drain and split-brain tests|needs the lab topology (T-412): four VMs and a test recursive resolver
no-egress|no-egress run (T-362, T-087)|needs the lab VMs with egress limited to the panel'

step_build() { go build -o "$bin" ./cmd/ctrlz-node; }

# -p 2 and a timeout keep a hung test from holding a runner or a machine. CONFORMANCE_RUN, a go test -run
# expression, narrows the test steps for debugging the suite on a small machine; a verdict for a bump is
# never taken from a run that sets it.
#
# The run is -v so that a skipped test is seen. Some tests in these packages skip on purpose when a
# library bump changes what they pin (dnsproxy no longer quoting the DoH query, "revisit D66"): a skip
# there is the very signal this suite exists to give, and a plain "ok" would hide it. So every skipped
# test is printed with its reason, and the step fails unless the reason is one of the environment skips
# of skip_is_environment below.
step_test() {
  run=""
  [ -z "${CONFORMANCE_RUN:-}" ] || run="-run $CONFORMANCE_RUN"
  log="$out/step-test.$$"
  rc=0
  # shellcheck disable=SC2086
  go test -v -count=1 -p 2 -timeout 20m $run "$@" >"$log" 2>&1 || rc=$?
  cat "$log"
  # A package with no test, or a -run that matches none, exits 0 and must not read as a pass.
  if grep -q -e 'no test files' -e 'no tests to run' "$log"; then
    echo "conformance: a package ran no test, which is a failure" >&2
    rc=1
  fi
  skips_judged "$log" || rc=1
  rm -f "$log"
  return "$rc"
}

# The skips that depend on the machine and say nothing about a library: no IPv6 loopback, no 127.0.0.2,
# and the Windows-only guards of tests that need a unix socket or a symlink rename. Anything else is a
# test that gave up, and the step fails on it by name. A reason is matched, not a test name, because
# the listener walk skips inside subtests whose names follow the transports.
skip_is_environment() {
  case "$1" in
    *"no IPv6 loopback here"* | *"cannot use 127.0.0.2 here"* | *"which is Linux"*) return 0 ;;
  esac
  return 1
}

# skips_judged <go test -v log>: print every skipped test with its reason and return 1 when one of them
# is not an environment skip. In -v output a test's log lines ("file_test.go:N: reason") follow its
# "=== RUN" or "=== NAME" header and its "--- SKIP:" line comes later, so the reason is kept per test.
skips_judged() {
  list=$(awk '
    /^=== (RUN|NAME|CONT) / { cur = $3; next }
    /^ *[A-Za-z0-9_]+_test\.go:[0-9]+: / { r = $0; sub(/^ *[A-Za-z0-9_]+_test\.go:[0-9]+: /, "", r); reason[cur] = r; next }
    /^ *--- SKIP: / { names[++k] = $3 }
    # A parent whose subtests all skipped is reported as skipped itself and has no reason of its own:
    # the subtests carry the reasons, so the parent is left out.
    END {
      for (i = 1; i <= k; i++) {
        parent = 0
        for (j = 1; j <= k; j++) if (index(names[j], names[i] "/") == 1) parent = 1
        if (!parent) print names[i] "\t" reason[names[i]]
      }
    }
  ' "$1")
  [ -n "$list" ] || return 0
  bad="$out/skip-bad.$$"
  : >"$bad"
  tab=$(printf '\t')
  echo "$list" | while IFS="$tab" read -r name why; do
    if skip_is_environment "$why"; then
      echo "conformance: SKIPPED (environment) $name: $why" >&2
    else
      echo "conformance: SKIPPED $name: $why" >&2
      echo x >>"$bad"
    fi
  done
  if [ -s "$bad" ]; then
    rm -f "$bad"
    echo "conformance: a test skipped itself for a reason that is not an environment one, which is a failure (a skip in these packages pins a library behaviour)" >&2
    return 1
  fi
  rm -f "$bad"
  return 0
}

# Exit status 77 is "skipped", the convention of automake test drivers.
step_unbound() {
  if ! command -v unbound >/dev/null 2>&1 && [ ! -x /usr/sbin/unbound ]; then
    echo "SKIP: no unbound binary on this machine" >&2
    return 77
  fi
  if [ "$(id -u)" != 0 ] && ! sudo -n true 2>/dev/null; then
    echo "SKIP: neither root nor passwordless sudo, which the lab address on lo needs" >&2
    return 77
  fi
  sh "$here/scripts/unbound-lab.sh"
}

step_vuln() {
  [ -x "$bin" ] || { echo "no built binary: the build step did not run" >&2; return 1; }
  if [ ! -x "$gobin/govulncheck" ] && [ ! -x "$gobin/govulncheck.exe" ]; then
    echo "govulncheck is not installed in $gobin" >&2
    return 1
  fi
  PATH="$gobin:$PATH" govulncheck -mode=binary "$bin"
}

# The licence scan reads the modules the binary was built from (go version -m, so it is the binary's own
# list and not go.mod's) and classifies each module's licence file by its text. Allowed: Apache-2.0, MIT,
# BSD 2 and 3 clause, ISC, Unlicense (AdGuard's libraries and dnsstamps). A module with no licence file, or one the scan cannot place, fails by name
# and is a reviewed addition, never a silent pass. Our own modules (shared) are not third party.
step_licences() {
  [ -x "$bin" ] || { echo "no built binary: the build step did not run" >&2; return 1; }
  mods=$(go version -m "$bin" | awk -F'\t' '$2 == "dep" { print $3 " " $4 }')
  [ -n "$mods" ] || { echo "the binary lists no module, so the scan cannot judge it" >&2; return 1; }
  : >"$out/licence-bad"
  echo "$mods" | while read -r path ver; do
    case "$path" in github.com/Kup1ng/*) continue ;; esac
    dir=$(go list -m -f '{{.Dir}}' "$path@$ver" 2>/dev/null || true)
    if [ -z "$dir" ] || [ ! -d "$dir" ]; then
      echo "licences: $path $ver is not in the module cache" >&2
      echo "$path" >>"$out/licence-bad"
      continue
    fi
    file=$(ls "$dir" | grep -i -E '^(LICEN[CS]E|COPYING|UNLICENSE)([.-].*)?$' | head -n 1 || true)
    if [ -z "$file" ]; then
      echo "licences: $path $ver has no licence file" >&2
      echo "$path" >>"$out/licence-bad"
      continue
    fi
    txt=$(cat "$dir/$file")
    kind=""
    case "$txt" in
      *"Apache License"*"Version 2.0"*) kind=Apache-2.0 ;;
      *"Permission is hereby granted, free of charge"*) kind=MIT ;;
      *"Redistribution and use in source and binary forms"*) kind=BSD ;;
      *"free and unencumbered software released into the public domain"*) kind=Unlicense ;;
      *"Permission to use, copy, modify, and/or distribute"* | *"Permission to use, copy, modify, and distribute"*) kind=ISC ;;
    esac
    if [ -z "$kind" ]; then
      echo "licences: $path $ver: the licence in $file is not one the scan knows" >&2
      echo "$path" >>"$out/licence-bad"
    else
      echo "licences: $path $ver $kind"
    fi
  done
  if [ -s "$out/licence-bad" ]; then
    echo "licences: not allowed or not placed:" >&2
    sort -u "$out/licence-bad" >&2
    return 1
  fi
  return 0
}

mode=run
only=""
while [ $# -gt 0 ]; do
  case "$1" in
    --list) mode=list ;;
    --only) shift; only=${1:?--only needs a comma-separated list of step names} ;;
    *) echo "conformance: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

wanted() {
  [ -z "$only" ] && return 0
  case ",$only," in *",$1,"*) return 0 ;; esac
  return 1
}

if [ "$mode" = list ]; then
  echo "$steps" | while IFS='|' read -r name desc cmd; do
    printf '%-11s %s\n            runs: %s\n' "$name" "$desc" "$cmd"
  done
  echo "$skipped" | while IFS='|' read -r name desc why; do
    printf '%-11s SKIPPED %s (%s)\n' "$name" "$desc" "$why"
  done
  exit 0
fi
if [ -n "$only" ]; then
  for o in $(echo "$only" | tr ',' ' '); do
    echo "$steps" | cut -d'|' -f1 | grep -qx "$o" || { echo "conformance: no step named $o" >&2; exit 2; }
  done
fi

: >"$out/results"
echo "$steps" | while IFS='|' read -r name desc cmd; do
  wanted "$name" || continue
  # The binary steps need the build even when only they are asked for.
  case "$name" in
    vuln | licences) [ -x "$bin" ] || step_build >"$out/build.log" 2>&1 || true ;;
  esac
  echo "== $name: $desc"
  rc=0
  $cmd >"$out/$name.log" 2>&1 || rc=$?
  if [ "$rc" = 0 ]; then
    echo "PASS $name" | tee -a "$out/results"
  elif [ "$rc" = 77 ]; then
    tail -n 3 "$out/$name.log"
    echo "SKIPPED $name" | tee -a "$out/results"
  else
    tail -n 40 "$out/$name.log"
    echo "FAIL $name (full log $out/$name.log)" | tee -a "$out/results"
  fi
done
# The lab parts are listed only on a full run, so --only never claims them.
if [ -z "$only" ]; then
  echo "$skipped" | while IFS='|' read -r name desc why; do
    echo "SKIPPED $name: $desc, $why" | tee -a "$out/results"
  done
fi

pass=$(grep -c '^PASS' "$out/results" || true)
fail=$(grep -c '^FAIL' "$out/results" || true)
skip=$(grep -c '^SKIPPED' "$out/results" || true)
echo "conformance: $pass passed, $fail failed, $skip skipped (logs in $out)"
if [ "$fail" != 0 ] || [ "$pass" = 0 ]; then
  echo "conformance: FAIL"
  exit 1
fi
if [ "$skip" != 0 ]; then
  echo "conformance: PASS (the skipped parts did not run; the reduced review of D54 needs them green in the lab too)"
else
  echo "conformance: PASS"
fi
