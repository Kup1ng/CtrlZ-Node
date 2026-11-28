# Lab topology of the node (p4-nodes 11.7, T-421)

Notes for whoever builds the lab. The tests that run on it are in 11.7; this file is
only how to get the machines to the state those tests start from.

## Machines

- One panel host (Docker Compose of the Panel repository, `CTRLZ_ENV` not
  `production`, a lab build with the `ctrlz_lab` tag).
- Four node hosts A, B, C and D: clean Ubuntu 24.04 server images (amd64), each with
  two addresses (`DNS_IP` and `PROXY_IP`; bind and advertised equal in the lab), on one
  private network with the panel. Only TCP 9443 to the panel and UDP 123 to the panel
  are needed by a node; nothing else leaves it.
- Zone `dns.ctrlz.test`, private CAs, the fixture catalog. No public certificate.

Pairs (11.7): the global pair is (A, B); the others are (B, A), (C, D) and (D, C).
Every node has at most one peer.

## The lab bundle

Dev and lab bundles are signed by the lab test root whose keys are public on purpose
(`internal/labroot/testdata`). Its key ids are on the deny list of every binary built
without the `ctrlz_lab` tag, so a production node refuses it at install and at load.

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags ctrlz_lab -o out/ctrlz-verify ./cmd/ctrlz-verify
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags ctrlz_lab -o out/ctrlz-node   ./cmd/ctrlz-node
go build -tags ctrlz_lab -o out/ctrlz-bundle ./cmd/ctrlz-bundle
out/ctrlz-bundle build --out out/bundle/1 --version 1 --min-version 1 --created $(date +%s) \
    --expires $(($(date +%s) + 31536000)) --packaging packaging \
    --node-bin out/ctrlz-node --verify-bin out/ctrlz-verify --debs out/debs
out/ctrlz-bundle sign-lab --dir out/bundle/1 \
    --seed internal/labroot/testdata/root-1.seed --seed internal/labroot/testdata/root-2.seed
```

`out/debs` holds `unbound`, `dns-root-data`, `chrony`, `nftables` and `polkitd` with the
dependency closure a clean 24.04 server image lacks. The release job computes that
closure against the image; for a lab, `apt-get download` on a connected 24.04 machine
with the same packages is enough. The Unbound revision must be `1.19.2-1ubuntu3.1` or
newer, or `apply.sh` refuses it.

The panel serves `out/bundle/1` under `deploy/bundles/node/1/` and `root.json` (the lab
root) as its `/install/root.json`. The install command then comes from the admin page as
in 4.2 step 1.

## Enrolling the four

For each host: paste the command, read the fingerprint the agent prints
(`journalctl -u ctrlz-agent`), compare it with the admin page, confirm, approve. With
`dns_zone` unset (T-089) each node serves Plain DNS on the placeholder zone with
private-CA certificates. Install the nodes before the panel is upgraded to anything that
needs them (the runbook's deployment order).

## What the container install test does not cover

`internal/installtest` runs the install and the upgrade on a clean `ubuntu:24.04`
container with no network and stubs for `systemctl`, `curl` and `apt-get`. It cannot
show that systemd accepts the units, that polkit applies the rule, that AppArmor lets the
Unbound units read `/etc/ctrlz/unbound`, that the chronyd profile lets chrony read the drop-in, that the agent unit starts under its seccomp filter, or that a stock `systemd-timesyncd` is replaced by chrony. Those are
checked once on a lab host after the first install:

```sh
systemd-analyze verify /etc/systemd/system/ctrlz-*.service
systemctl is-active ctrlz-agent ctrlz-dns ctrlz-proxy
sudo -u ctrlz-agent systemctl restart ctrlz-dns.service        # allowed
sudo -u ctrlz-agent systemctl restart ssh.service              # refused by polkit
aa-status | grep unbound                                       # profile in enforce mode
sudo -u ctrlz-agent unbound-control -c /etc/ctrlz/unbound/identified.conf status
chronyc sources                                                # the panel, NTS
aa-status | grep chronyd; journalctl -k | grep -i "apparmor=\"DENIED\""   # no denial for /etc/ctrlz/chrony
systemctl status ctrlz-agent                                   # running: no EPERM from chmod of a setgid directory
systemctl status systemd-timesyncd                             # gone: the install removed it for chrony
```
