# Ctrl Z Node

The DNS node of Ctrl Z (`github.com/Kup1ng/CtrlZ-Node`). One binary, three
systemd services:

| Role | Command | Job |
|---|---|---|
| `dns` | `ctrlz-node dns` | UDP/TCP 53, DoT, DoH and DoQ on `DNS_IP`; the query pipeline |
| `proxy` | `ctrlz-node proxy` | ports 80 and 443 on `PROXY_IP`; Grant check, splice to Xray |
| `agent` | `ctrlz-node agent` | the mTLS link to the panel hub; applies config entries; manages Xray, Unbound, certificates, updates |

Xray and Unbound run as separate services. The node answers from its own disk,
so it keeps serving when the panel is down.

**Status: stubs.** The layout compiles and the shared module is wired in; no
role does real work yet (phase P4). Running a role prints `not implemented yet`
and exits with code 3.

## Layout

```text
cmd/ctrlz-node/      the one binary and its role switch
internal/config/     local, pre-panel configuration
internal/dns/        sockets and the query pipeline (glue around shared code)
internal/proxy/      80/443 front end
internal/agent/      hub link and apply loop (uses shared quarantine.Apply)
internal/policy/     hot-path glue around the shared evaluator; runs the golden vectors
internal/store/      persistence of the config log, blobs, tables, quarantine
internal/cache/      true-answer cache
internal/resolve/    Unbound and upstream routing (uses shared route)
internal/grant/      the Grant table
internal/telemetry/  logs, counters, activity heartbeat
internal/xray/       Xray process management
internal/certs/      mTLS and serving certificates
shared/              identical copy of "Ctrl Z Panel/shared"
scripts/             shared-sync, shared-verify, ci (thin wrappers, .sh and .ps1)
```

`packaging/` and `deploy/` from the plan are added when there is something to
put in them.

## The shared module

`shared/` is the same Go module as in the Panel repository, imported as
`github.com/Kup1ng/CtrlZ-Shared` through
`replace github.com/Kup1ng/CtrlZ-Shared => ./shared` in `go.mod`. **Do not edit
it here.** `Ctrl Z Panel/shared` is canonical: change it there, then

```text
scripts/shared-sync.sh        (or .ps1)     # pulls the Panel copy in
scripts/shared-verify.sh      (or .ps1)     # both copies must have the same tree hash
```

`shared` is a nested module, so `go test ./...` here does not run its tests;
`scripts/ci.sh` runs both, after verifying the copy.

`internal/policy` runs every shared golden vector (`TestGoldenVectors`). Today
that uses the shared reference harness; in P4 it is replaced by a harness over
the real glue, on the same files, so a node that drifts from the shared
evaluator fails there.

## Before the first commit

```sh
git config core.hooksPath .githooks
```

Every commit then passes a `gitleaks` scan of what is staged. `scripts/ci.sh` scans the whole history and runs `govulncheck`. Install both with `go install`: `github.com/zricethezav/gitleaks/v8@latest` and `golang.org/x/vuln/cmd/govulncheck@latest`. A missing tool fails the run, because it must not read as a clean result.

## Build

```text
go build ./...
go vet ./...
go test ./...
go run ./cmd/ctrlz-node version
```

Go 1.27.4. A release stamps the version with
`-ldflags "-X main.version=<version>"`.

## Proof queries (to build in P4)

A query for `<label>.verify.<zone>` is answered, over UDP, with a TXT record that
holds the proof code (shared contract 3.5, `identity.ProofCode` with the
`proof_key` of `NodeConfig`). The node reports **every** proof query, UDP
included, to the hub with `ProofObservation` and the transport it arrived on;
the hub derives the same code and records the observation, after it has
checked the message with `wire.ValidateNodeMessage`. The node never logs the
code.
