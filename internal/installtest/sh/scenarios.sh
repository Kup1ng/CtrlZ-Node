#!/bin/sh
# Install test scenarios (p4-nodes 11.5, 11.2 N7 and N11), run inside a clean
# ubuntu:24.04 container with no network. Usage: scenarios.sh NAME
#
# systemctl, sysctl, modprobe, journalctl, curl and apt-get are stubs (the
# container has no systemd and no network); the bundle is a fake one with dummy
# .deb files built here with dpkg-deb. Everything else is real: node.sh, apply.sh,
# ctrlz-verify (the real binary), the bundle builder, dpkg, useradd and friends.
# /work is the read-only mount from internal/installtest.
set -u
W=/work
SCEN=${1:-}
PIN='sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
TOKEN='tkn_Q3f9Z0-TestTokenValue_8c2e41aa77'

fail() {
	echo "FAIL $SCEN: $*" >&2
	exit 1
}
eq() { [ "$1" = "$2" ] || fail "$3: got '$1', want '$2'"; }
nothing_installed() {
	getent passwd ctrlz-agent >/dev/null && fail "$1: the user ctrlz-agent exists"
	getent group ctrlz >/dev/null && fail "$1: the group ctrlz exists"
	[ -e /etc/ctrlz ] && fail "$1: /etc/ctrlz exists"
	[ -e /var/lib/ctrlz ] && fail "$1: /var/lib/ctrlz exists"
	[ -e /usr/local/bin/ctrlz-node ] && fail "$1: the binary is installed"
	[ -e /var/log/stub/apt.log ] && fail "$1: apt-get ran"
	grep -q 'start\|enable' /var/log/stub/calls.log 2>/dev/null && fail "$1: systemctl was asked to enable or start"
	return 0
}
no_leak() {
	[ ! -e /var/log/stub/LEAK ] || fail "$1: $(cat /var/log/stub/LEAK)"
}

# --- the host and the hub --------------------------------------------------------

setup_host() {
	for n in systemctl sysctl modprobe journalctl; do
		cp "$W/sh/stub.sh" "/usr/local/bin/$n"
		chmod 0755 "/usr/local/bin/$n"
	done
	cp "$W/sh/stub-curl.sh" /usr/local/bin/curl
	cp "$W/sh/stub-apt-get.sh" /usr/local/bin/apt-get
	chmod 0755 /usr/local/bin/curl /usr/local/bin/apt-get
	mkdir -p /stubcfg /var/log/stub
	# The ubuntu container image ships its own policy-rc.d (exit 101); a real host has none.
	# Without this the scenarios could not tell the install's policy-rc.d from the image's.
	rm -f /usr/sbin/policy-rc.d
	printf '%s' "$PIN" >/stubcfg/pin
	printf '%s' "$TOKEN" >/stubcfg/token
	printf 'Authorization: Bearer %s\n' "$TOKEN" >/stubcfg/token.hdr
}

mkdeb() { # name version [extra control fields, \n separated]
	d=/tmp/debbuild/$1
	rm -rf "$d"
	mkdir -p "$d/DEBIAN" "$d/usr/share/ctrlz-test"
	{
		printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: test <test@example.invalid>\n' "$1" "$2"
		[ -z "${3:-}" ] || printf '%b\n' "$3"
		printf 'Description: stand-in for the install test\n'
	} >"$d/DEBIAN/control"
	echo "$1" >"$d/usr/share/ctrlz-test/$1"
	dpkg-deb --root-owner-group --build "$d" "/tmp/debs/$1_$2_all.deb" >/dev/null || fail "dpkg-deb $1"
}

# mkhub VERSION [VERIFY_BIN] [UNBOUND_VERSION] [good|one|online]: a signed bundle of
# fake packages and a fake node binary, laid out as the hub serves it.
mkhub() {
	v=$1
	vb=${2:-$W/bin/verify-lab}
	uv=${3:-1.19.2-1ubuntu3.1}
	sign=${4:-good}
	rm -rf /tmp/debs /tmp/debbuild
	mkdir -p /tmp/debs /hub/install/bundle
	mkdeb unbound "$uv"
	mkdeb dns-root-data 2023010101
	# Like the real package: it provides and conflicts with time-daemon, as does systemd-timesyncd.
	mkdeb chrony 4.5-1ubuntu4 'Provides: time-daemon
Conflicts: time-daemon'
	mkdeb nftables 1.0.9-1
	mkdeb polkitd 124-2
	printf '#!/bin/sh\necho node-%s\n' "$v" >"/tmp/fake-node-$v"
	"$W/bin/bundle-lab" build --out "/hub/install/bundle/$v" --version "$v" --min-version 1 --created 1 --expires 4102444800 \
		--packaging "$W/packaging" --node-bin "/tmp/fake-node-$v" --verify-bin "$vb" --debs /tmp/debs >/dev/null || fail 'bundle build'
	case $sign in
	good) seeds='root-1 root-2' ;;
	one) seeds='root-1' ;;
	online) seeds='policy catalog' ;;
	*) fail "mkhub: sign $sign" ;;
	esac
	a=
	for s in $seeds; do a="$a --seed $W/lab/$s.seed"; done
	# shellcheck disable=SC2086
	"$W/bin/bundle-lab" sign-lab --dir "/hub/install/bundle/$v" $a || fail 'sign'
	cp "$W/lab/root.json" /hub/install/root.json
	printf -- '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n' >/hub/install/node_ca.pem
	cp "$vb" /hub/install/ctrlz-verify
	cp "/hub/install/bundle/$v/packaging/install/node.sh" /tmp/ctrlz-node.sh
	ROOTSHA=$(sha256sum /hub/install/root.json | cut -d' ' -f1)
}

run_install() {
	printf %s "$TOKEN" | sh /tmp/ctrlz-node.sh --hub hub.example --pin "$PIN" --token-stdin --root "$ROOTSHA" \
		--dns-bind-ip 10.0.0.5 --dns-advertised-ip 203.0.113.5 --proxy-bind-ip 10.0.0.6 --proxy-advertised-ip 203.0.113.6 "$@"
}

# The sampler looks at every process's command line and environment, every 20 ms,
# for the token: the install test's "no ps output sampled through the install" (N7).
start_sampler() {
	: >/var/log/stub/sampler.hits
	(
		while [ ! -e /tmp/sampler.stop ]; do
			if grep -aqF -f /stubcfg/token /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null; then
				echo hit >>/var/log/stub/sampler.hits
			fi
			sleep 0.02
		done
	) &
	SAMPLER=$!
}
stop_sampler() {
	: >/tmp/sampler.stop
	wait "$SAMPLER" 2>/dev/null
	rm -f /tmp/sampler.stop
	[ ! -s /var/log/stub/sampler.hits ] || fail 'the token was in the command line or environment of a process'
}

mode_of() { stat -c '%a' "$1"; }
own_of() { stat -c '%U:%G' "$1"; }

# --- N11 and the layout, checked on the installed host ----------------------------------

check_layout() {
	grp=$(getent group ctrlz | cut -d: -f4 | tr ',' '\n' | sort | tr '\n' ' ')
	eq "$grp" 'ctrlz-agent ctrlz-dns ' 'members of group ctrlz'
	for u in ctrlz-proxy ctrlz-unbound ctrlz-unbound-free; do
		id -nG "$u" | tr ' ' '\n' | grep -qx ctrlz && fail "$u is in group ctrlz"
		eq "$(id -gn "$u")" "$u" "primary group of $u"
	done
	eq "$(id -gn ctrlz-agent)" ctrlz-agent 'primary group of ctrlz-agent'
	eq "$(id -gn ctrlz-dns)" ctrlz-dns 'primary group of ctrlz-dns'

	# The installed unit and polkit files are the verified bundle's, byte for byte.
	while read -r src dest mode; do
		case $src in '' | '#'*) continue ;; esac
		[ "$src" = chrony/chrony.conf ] && continue
		cmp -s "$W/packaging/$src" "$dest" || fail "$dest differs from packaging/$src"
		eq "$(mode_of "$dest")" "$(echo "$mode" | sed 's/^0//')" "mode of $dest"
		eq "$(own_of "$dest")" root:root "owner of $dest"
	done <"$W/packaging/files.conf"
	cmp -s "$W/packaging/chrony/chrony.conf" /etc/chrony/chrony.conf || fail 'chrony.conf is not the fixed one'

	# What the agent may do (N11): the polkit rule has one grant, manage-units, for
	# exactly four units and three verbs; the agent unit writes to exactly three paths.
	rule=/etc/polkit-1/rules.d/50-ctrlz-agent.rules
	eq "$(grep -c 'action\.id ===' "$rule")" 1 'actions in the polkit rule'
	grep -q 'org.freedesktop.systemd1.manage-units' "$rule" || fail 'polkit: no manage-units'
	eq "$(grep -c 'polkit.Result.YES' "$rule")" 1 'grants in the polkit rule'
	units=$(grep -A6 'var units' "$rule" | grep -o '"[a-z.-]*service"' | tr -d '"' | sort | tr '\n' ' ')
	eq "$units" 'chrony.service ctrlz-dns.service ctrlz-unbound-free.service ctrlz-unbound.service ' 'polkit units'
	eq "$(grep '^ReadWritePaths=' /etc/systemd/system/ctrlz-agent.service)" 'ReadWritePaths=/var/lib/ctrlz /etc/ctrlz/unbound /etc/ctrlz/chrony' 'agent writable paths'
	eq "$(grep -c '^LimitCORE=0$' /etc/systemd/system/ctrlz-dns.service /etc/systemd/system/ctrlz-agent.service /etc/systemd/system/ctrlz-proxy.service /etc/systemd/system/ctrlz-unbound.service /etc/systemd/system/ctrlz-unbound-free.service | grep -c ':1$')" 5 'units with LimitCORE=0'
	grep -q '^Storage=none$' /etc/systemd/coredump.conf.d/ctrlz.conf || fail 'coredump Storage'
	grep -q '^ProcessSizeMax=0$' /etc/systemd/coredump.conf.d/ctrlz.conf || fail 'coredump ProcessSizeMax'
	grep -q '^CPUQuota=[0-9]*%$' /etc/systemd/system/ctrlz-unbound-free.service.d/10-limits.conf || fail 'free unbound CPUQuota drop-in'

	# Directories: owner, group, mode and setgid exactly as dirs.conf says.
	while read -r p o g m; do
		case $p in '' | '#'*) continue ;; esac
		eq "$(own_of "$p")" "$o:$g" "owner of $p"
		eq "$(mode_of "$p")" "$(echo "$m" | sed 's/^0//')" "mode of $p"
	done <"$W/packaging/dirs.conf"

	eq "$(own_of /usr/local/bin/ctrlz-node)" root:root 'owner of ctrlz-node'
	eq "$(mode_of /usr/local/bin/ctrlz-node)" 755 'mode of ctrlz-node'
	eq "$(own_of /usr/local/sbin/ctrlz-verify)" root:root 'owner of ctrlz-verify'
	[ -e /usr/local/bin/ctrlz-verify ] && fail 'ctrlz-verify is in the agent-reachable bin dir'

	# Packages came from the bundle, with apt's sources off, and nothing else ran.
	eq "$(grep -c 'install' /var/log/stub/apt.log)" "$(wc -l </var/log/stub/apt.log)" 'apt-get is only asked to install'
	grep -q 'Dir::Etc::sourcelist=/dev/null' /var/log/stub/apt.log || fail 'apt: sourcelist not disabled'
	grep -q 'Dir::Etc::sourceparts=/dev/null' /var/log/stub/apt.log || fail 'apt: sourceparts not disabled'
	# Real apt refuses --no-download together with local .deb files (p4n-W5c-r5-1).
	grep -q -- '--no-download' /var/log/stub/apt.log && fail 'apt: --no-download is refused by real apt with local files'
	grep -qE '(^| )(update|upgrade|dist-upgrade|download)( |$)' /var/log/stub/apt.log && fail 'apt: an index or download command ran'
	for p in unbound dns-root-data chrony nftables polkitd; do
		eq "$(dpkg-query -W -f='${db:Status-Status}' "$p")" installed "package $p"
	done
	grep -q 'mask unbound.service' /var/log/stub/calls.log || fail 'the distribution unbound is not masked'

	# The Unbound units are the agent's to start: not enabled by the install.
	grep -E '^systemctl enable' /var/log/stub/calls.log | grep -q 'ctrlz-unbound' && fail 'an Unbound unit was enabled'
	grep -E '^systemctl (start|restart)' /var/log/stub/calls.log | grep -q 'ctrlz-unbound' && fail 'an Unbound unit was started by the install'
	return 0
}

check_agent_files() {
	eq "$(cat /etc/ctrlz/agent.conf)" '# Written by the install (p4-nodes 4.2); read by the agent and by dns.
hub=hub.example
dns_bind_ip=10.0.0.5
dns_advertised_ip=203.0.113.5
proxy_bind_ip=10.0.0.6
proxy_advertised_ip=203.0.113.6' 'agent.conf'
	K=/var/lib/ctrlz/keys
	for f in root.json node_ca.pem hub.pin enroll.token; do
		eq "$(own_of $K/$f)" ctrlz-agent:ctrlz "owner of keys/$f"
		eq "$(mode_of $K/$f)" 600 "mode of keys/$f"
	done
	cmp -s "$K/root.json" /hub/install/root.json || fail 'keys/root.json'
	cmp -s /etc/ctrlz/root.json /hub/install/root.json || fail '/etc/ctrlz/root.json'
	eq "$(own_of /etc/ctrlz/root.json)" root:root 'owner of the root-owned root.json'
	eq "$(cat $K/hub.pin)" "$PIN" 'keys/hub.pin'
	eq "$(cat $K/enroll.token)" "$TOKEN" 'keys/enroll.token'
	[ ! -e $K/node.key ] && [ ! -e $K/node.crt ] || fail 'a node key or certificate exists before enrolment'
}

# The token is on disk in one place: the agent's keys/enroll.token, which Enroll
# consumes. Nowhere else on the host, and no log.
check_token_only_in_keys() {
	hits=$(grep -rlaF -f /stubcfg/token /etc /var /run /root /tmp /home /opt /usr/local /srv 2>/dev/null | grep -v '^/var/log/stub/' | sort | tr '\n' ' ')
	eq "$hits" '/var/lib/ctrlz/keys/enroll.token ' 'files holding the token'
	grep -raF -f /stubcfg/token /var/log/stub 2>/dev/null && fail 'the token is in a stub log'
	ls /run/ctrlz-install.* /var/tmp/ctrlz-install.* >/dev/null 2>&1 && fail 'the installer left its working directories'
	return 0
}

# --- scenarios ------------------------------------------------------------------------

sc_happy() {
	setup_host
	mkhub 3
	start_sampler
	run_install >/tmp/out 2>&1 || {
		cat /tmp/out
		fail 'install exited non-zero'
	}
	stop_sampler
	no_leak install
	check_layout
	check_agent_files
	check_token_only_in_keys
	check_download_bounds 3
	eq "$(cat /etc/ctrlz/versions/node)" 3 'installed version'
	grep -q -- '--pinnedpubkey' /var/log/stub/curl.args || fail 'no pin'
	# The order of fetches: root.json first, then the CA, the verifier, the bundle.
	eq "$(sed -n 1,3p /var/log/stub/fetch.log | tr '\n' ' ')" '/install/root.json /install/node_ca.pem /install/ctrlz-verify ' 'first fetches'
	eq "$(sed -n 4p /var/log/stub/fetch.log)" /install/bundle/3/manifest.json 'fourth fetch'
	grep -E '^systemctl enable' /var/log/stub/calls.log | grep -q 'ctrlz-agent.service ctrlz-dns.service ctrlz-proxy.service' || fail 'units not enabled'
	grep -qE '^systemctl restart ctrlz-agent.service ctrlz-dns.service ctrlz-proxy.service' /var/log/stub/calls.log || fail 'units not started'
	grep -qE '^systemctl stop ctrlz-agent.service ctrlz-dns.service ctrlz-proxy.service' /var/log/stub/calls.log || fail 'the units that run as the agent were not stopped first'
	# The packages go in first (a failure there leaves the node running); then the stop,
	# before anything of the agent's tree is touched and before any enable or restart:
	# the first systemctl call that is not about the distribution's own units.
	eq "$(grep -v -e '^systemctl mask ' -e '^systemctl disable ' -e '^systemctl is-active ' /var/log/stub/calls.log | sed -n 1p)" 'systemctl stop ctrlz-agent.service ctrlz-dns.service ctrlz-proxy.service' 'first systemctl call that changes the node'

	# A second run of the same bundle (a repair) leaves the same state and the same groups.
	: >/var/log/stub/apt.log
	: >/var/log/stub/calls.log
	rm -f /var/log/stub/fetch.log
	run_install >/tmp/out2 2>&1 || {
		cat /tmp/out2
		fail 'second install exited non-zero'
	}
	no_leak 'second install'
	# The repair replaced the identity files and the binary, so the running units must be restarted.
	grep -qE "^systemctl restart ctrlz-agent.service ctrlz-dns.service ctrlz-proxy.service" /var/log/stub/calls.log || fail "a repeat install did not restart the units"
	check_layout
	check_agent_files
	echo "PASS $SCEN"
}

sc_os_release() {
	setup_host
	mkhub 3
	for rel in 'ID=ubuntu
VERSION_ID="22.04"' 'ID=ubuntu
VERSION_ID="26.04"' 'ID=debian
VERSION_ID="12"' 'ID=ubuntu
VERSION_ID="24.10"' 'ID=ubuntu-core
VERSION_ID="24.04"' ''; do
		printf '%s\n' "$rel" >/etc/os-release
		before=$(find /etc /var/lib /usr/local /run /root /home /opt /srv -xdev 2>/dev/null | sort | sha256sum)
		rm -f /var/log/stub/fetch.log /var/log/stub/curl.args
		if run_install >/tmp/out 2>&1; then fail "install ran on: $rel"; fi
		grep -q 'not Ubuntu 24.04' /tmp/out || fail "no refusal message for: $rel"
		after=$(find /etc /var/lib /usr/local /run /root /home /opt /srv -xdev 2>/dev/null | sort | sha256sum)
		eq "$after" "$before" "the host changed for: $rel"
		[ ! -e /var/log/stub/curl.args ] || fail "curl was called on: $rel"
		nothing_installed "os-release $rel"
	done
	echo "PASS $SCEN"
}

sc_wrong_root() {
	setup_host
	mkhub 3
	ROOTSHA=$(printf x | sha256sum | cut -d' ' -f1)
	if run_install >/tmp/out 2>&1; then fail 'install ran with a wrong --root'; fi
	grep -q 'root.json does not match' /tmp/out || fail 'no message'
	eq "$(cat /var/log/stub/fetch.log | tr '\n' ' ')" '/install/root.json ' 'nothing is fetched after a wrong root'
	nothing_installed 'wrong root'
	no_leak 'wrong root'
	echo "PASS $SCEN"
}

sc_wrong_verify() {
	setup_host
	mkhub 3
	# A verifier that is not the one the script was stamped with. It would leave a
	# marker if it ran; the script must refuse it by its hash first.
	printf '#!/bin/sh\ntouch /tmp/VERIFIER-RAN\nexit 0\n' >/hub/install/ctrlz-verify
	if run_install >/tmp/out 2>&1; then fail 'install ran with a wrong ctrlz-verify'; fi
	grep -q 'ctrlz-verify does not match' /tmp/out || fail 'no message'
	[ ! -e /tmp/VERIFIER-RAN ] || fail 'the tampered verifier ran'
	eq "$(tr '\n' ' ' </var/log/stub/fetch.log)" '/install/root.json /install/node_ca.pem /install/ctrlz-verify ' 'fetches'
	nothing_installed 'wrong verifier'
	echo "PASS $SCEN"
}

sc_wrong_script() {
	# node.sh not stamped by the release job (placeholder left in): refused at once.
	setup_host
	mkhub 3
	cp "$W/packaging/install/node.sh" /tmp/ctrlz-node.sh
	if run_install >/tmp/out 2>&1; then fail 'an unstamped script ran'; fi
	grep -q 'not stamped' /tmp/out || fail 'no message'
	[ ! -e /var/log/stub/curl.args ] || fail 'curl ran'
	nothing_installed 'unstamped'
	echo "PASS $SCEN"
}

sc_outside_grant() {
	setup_host
	mkhub 3 "$W/bin/verify-lab" 1.19.2-1ubuntu3.1 online
	if run_install >/tmp/out 2>&1; then fail 'a manifest signed by the online keys installed'; fi
	grep -q 'did not verify' /tmp/out || fail 'no message'
	eq "$(tail -n +4 /var/log/stub/fetch.log | tr '\n' ' ')" '/install/bundle/3/manifest.json ' 'nothing of the bundle but its manifest is fetched'
	nothing_installed 'outside the bundle grant'
	echo "PASS $SCEN"
}

sc_one_signature() {
	setup_host
	mkhub 3 "$W/bin/verify-lab" 1.19.2-1ubuntu3.1 one
	if run_install >/tmp/out 2>&1; then fail 'a manifest with one of two signatures installed'; fi
	nothing_installed 'one signature'
	echo "PASS $SCEN"
}

sc_file_tampered() {
	setup_host
	mkhub 3
	f=/hub/install/bundle/3/debs/unbound_1.19.2-1ubuntu3.1_all.deb
	size=$(stat -c %s "$f")
	# Same size, other bytes: only the hash can tell.
	head -c "$size" /dev/zero | tr '\0' 'A' >"$f"
	if run_install >/tmp/out 2>&1; then fail 'a bundle with a tampered file installed'; fi
	grep -q 'did not verify' /tmp/out || fail 'no message'
	nothing_installed 'tampered file'
	echo "PASS $SCEN"
}

sc_file_not_listed() {
	# The verifier itself, on a directory with a file that the manifest does not
	# list (a path the script would never fetch, so this is the check that holds if
	# anything else ever puts one there), and with a symlink.
	setup_host
	mkhub 3
	cp -r /hub/install/bundle/3 /tmp/stage
	"$W/bin/verify-lab" check --root /hub/install/root.json --manifest /tmp/stage/manifest.json --dir /tmp/stage --version 3 || fail 'a good bundle failed'
	echo x >/tmp/stage/debs/evil.deb
	"$W/bin/verify-lab" check --root /hub/install/root.json --manifest /tmp/stage/manifest.json --dir /tmp/stage >/tmp/out 2>&1
	eq "$?" 13 'exit code for a file not in the index'
	grep -q 'file-not-listed' /tmp/out || fail 'message does not name the check'
	grep -q evil /tmp/out && fail 'message echoes the file name'
	rm /tmp/stage/debs/evil.deb
	rm /tmp/stage/bin/ctrlz-node
	ln -s /etc/passwd /tmp/stage/bin/ctrlz-node
	"$W/bin/verify-lab" check --root /hub/install/root.json --manifest /tmp/stage/manifest.json --dir /tmp/stage >/tmp/out 2>&1
	eq "$?" 13 'exit code for a symlink'
	grep -q 'file-not-regular' /tmp/out || fail 'a symlink was not refused as not regular'
	echo "PASS $SCEN"
}

sc_lab_root_in_production() {
	# A production-built ctrlz-verify (no ctrlz_lab tag) must refuse the lab root,
	# although the bundle is validly signed by it: the install is refused before any
	# file of the bundle is fetched.
	setup_host
	mkhub 3 "$W/bin/verify-prod"
	if run_install >/tmp/out 2>&1; then fail 'a production verifier accepted the lab root'; fi
	grep -q 'did not verify' /tmp/out || fail 'no message'
	"$W/bin/verify-prod" list --root /hub/install/root.json --manifest /hub/install/bundle/3/manifest.json >/tmp/out2 2>&1
	eq "$?" 10 'exit code for a lab root'
	grep -q 'root-lab-key' /tmp/out2 || fail 'message does not name the check'
	eq "$(tail -n +4 /var/log/stub/fetch.log | tr '\n' ' ')" '/install/bundle/3/manifest.json ' 'no bundle file fetched'
	nothing_installed 'lab root in production'
	echo "PASS $SCEN"
}

sc_old_unbound() {
	setup_host
	mkhub 3 "$W/bin/verify-lab" 1.18.0-1
	if run_install >/tmp/out 2>&1; then fail 'an Unbound under the version floor installed'; fi
	grep -q 'under the version floor' /tmp/out || fail 'no message'
	grep -qE '^systemctl (start|restart|enable)' /var/log/stub/calls.log 2>/dev/null && fail 'a unit was enabled or started'
	[ ! -e /etc/ctrlz/versions/node ] || fail 'the version was recorded'
	echo "PASS $SCEN"
}

sc_group_drift() {
	# Someone is already in group ctrlz: the install must not pass over it (N11's
	# install test lists group ctrlz: only ctrlz-dns and ctrlz-agent).
	setup_host
	mkhub 3
	groupadd --system ctrlz
	useradd --system -M -s /usr/sbin/nologin -g nogroup -G ctrlz intruder
	if run_install >/tmp/out 2>&1; then fail 'the install passed with an extra member in group ctrlz'; fi
	grep -q "group ctrlz has members" /tmp/out || fail 'no message'
	grep -qE '^systemctl (start|restart)' /var/log/stub/calls.log 2>/dev/null && fail 'a unit was started'
	echo "PASS $SCEN"
}

sc_token_arguments() {
	setup_host
	mkhub 3
	if printf %s "$TOKEN" | sh /tmp/ctrlz-node.sh --hub hub.example --pin "$PIN" --token "$TOKEN" --root "$ROOTSHA" >/tmp/out 2>&1; then fail 'a --token argument was accepted'; fi
	grep -q "$TOKEN" /tmp/out && fail 'the token was echoed'
	if sh /tmp/ctrlz-node.sh --hub hub.example --pin "$PIN" --token-stdin --root "$ROOTSHA" --dns-bind-ip 10.0.0.5 --proxy-bind-ip 10.0.0.6 </dev/null >/tmp/out 2>&1; then fail 'an empty stdin was accepted'; fi
	printf 'bad token with spaces\n' | sh /tmp/ctrlz-node.sh --hub hub.example --pin "$PIN" --token-stdin --root "$ROOTSHA" --dns-bind-ip 10.0.0.5 --proxy-bind-ip 10.0.0.6 >/tmp/out 2>&1 && fail 'a malformed token was accepted'
	[ ! -e /var/log/stub/curl.args ] || fail 'curl ran'
	nothing_installed 'token arguments'
	echo "PASS $SCEN"
}

sc_bad_addresses() {
	# A value that could carry a line into agent.conf is refused before any change.
	setup_host
	mkhub 3
	for bad in '10.0.0.5
evil=1' '10.0.0.5 x' 'not-an-ip' ''; do
		if printf %s "$TOKEN" | sh /tmp/ctrlz-node.sh --hub hub.example --pin "$PIN" --token-stdin --root "$ROOTSHA" \
			--dns-bind-ip "$bad" --proxy-bind-ip 10.0.0.6 >/tmp/out 2>&1; then fail "address accepted: $bad"; fi
	done
	nothing_installed 'bad addresses'
	# Strings that pass a check of characters and are not addresses the agent accepts are
	# refused as well, before the token goes to the hub (p4n-W5c-r6-3).
	for bad in 10.0.0.256 0.0.0.0 1.2.3 :: 1..2 256.1.1.1 ab.cd 224.0.0.1 ff02::1; do
		if printf %s "$TOKEN" | sh /tmp/ctrlz-node.sh --hub hub.example --pin "$PIN" --token-stdin --root "$ROOTSHA" \
			--dns-bind-ip "$bad" --proxy-bind-ip 10.0.0.6 >/tmp/out 2>&1; then fail "address accepted: $bad"; fi
		grep -q 'not one the node can run with' /tmp/out || fail "no message for $bad: $(cat /tmp/out)"
	done
	for bad in 10.0.0.1, ,10.0.0.1 10.0.0.1,,10.0.0.2 10.0.0.1,0.0.0.0; do
		if printf %s "$TOKEN" | sh /tmp/ctrlz-node.sh --hub hub.example --pin "$PIN" --token-stdin --root "$ROOTSHA" \
			--dns-bind-ip 10.0.0.5 --proxy-bind-ip 10.0.0.6 --panel-addrs "$bad" >/tmp/out 2>&1; then fail "panel addrs accepted: $bad"; fi
	done
	grep -q 'install/bundle' /var/log/stub/fetch.log 2>/dev/null && fail 'the bundle was fetched with a token for a bad address'
	nothing_installed 'bad addresses, semantic'
	# And good ones, IPv6 among them, pass the check.
	"$W/bin/verify-lab" addr 10.0.0.5 2001:db8::5 || fail 'good addresses refused'
	echo "PASS $SCEN"
}

# An upgrade after an install, through the real upgrade code, the root-owned
# ctrlz-verify and apply.sh. N11 runs again afterwards (7.1).
sc_upgrade() {
	setup_host
	mkhub 3
	run_install >/tmp/out 2>&1 || {
		cat /tmp/out
		fail 'install'
	}
	check_layout

	mkhub 4 "$W/bin/verify-lab" 1.20.0-1
	mkdir -p /var/lib/ctrlz/bundles/node
	cp -r /hub/install/bundle/4 /var/lib/ctrlz/bundles/node/4
	chown -R ctrlz-agent:ctrlz /var/lib/ctrlz/bundles
	before=$(cat /usr/local/bin/ctrlz-node)
	: >/var/log/stub/calls.log
	: >/var/log/stub/apt.log
	"$W/bin/upgradeshim" 4 >/tmp/out 2>&1 || {
		cat /tmp/out
		fail 'upgrade'
	}
	after=$(cat /usr/local/bin/ctrlz-node)
	[ "$after" != "$before" ] || fail 'the binary did not change'
	eq "$(cat /etc/ctrlz/versions/node)" 4 'version after the upgrade'
	grep -qE '^systemctl restart ctrlz-agent.service ctrlz-dns.service ctrlz-proxy.service' /var/log/stub/calls.log || fail 'units not restarted'
	eq "$(dpkg-query -W -f='${Version}' unbound)" 1.20.0-1 'unbound after the upgrade'
	check_layout
	# The agent's keys and the host's identity are untouched by an upgrade.
	eq "$(cat /etc/ctrlz/agent.conf | head -n 2 | tail -n 1)" hub=hub.example 'agent.conf kept'
	[ -e /var/lib/ctrlz/keys/enroll.token ] || fail 'an upgrade removed the keys of the host'
	ls /var/lib/ctrlz-upgrade-* >/dev/null 2>&1 && fail 'staging left behind'
	no_leak upgrade

	# Not above the installed version: refused, nothing changes.
	"$W/bin/upgradeshim" 4 >/tmp/out 2>&1 && fail 'an upgrade to the installed version ran'
	"$W/bin/upgradeshim" 3 >/tmp/out 2>&1 && fail 'a downgrade ran'
	eq "$(cat /etc/ctrlz/versions/node)" 4 'version after refused upgrades'
	echo "PASS $SCEN"
}

sc_upgrade_tampered() {
	setup_host
	mkhub 3
	run_install >/tmp/out 2>&1 || fail 'install'
	mkhub 5
	mkdir -p /var/lib/ctrlz/bundles/node
	cp -r /hub/install/bundle/5 /var/lib/ctrlz/bundles/node/5
	# The agent, which owns this directory, swaps a file after downloading it.
	printf 'evil' >/var/lib/ctrlz/bundles/node/5/bin/ctrlz-node
	before=$(cat /usr/local/bin/ctrlz-node)
	: >/var/log/stub/calls.log
	"$W/bin/upgradeshim" 5 >/tmp/out 2>&1 && fail 'a tampered bundle was installed'
	eq "$(cat /usr/local/bin/ctrlz-node)" "$before" 'the binary changed'
	eq "$(cat /etc/ctrlz/versions/node)" 3 'version after a refused upgrade'
	grep -qE '^systemctl (start|restart)' /var/log/stub/calls.log 2>/dev/null && fail 'a unit was restarted'

	# An unsigned/under-signed bundle of version 6.
	mkhub 6 "$W/bin/verify-lab" 1.19.2-1ubuntu3.1 online
	cp -r /hub/install/bundle/6 /var/lib/ctrlz/bundles/node/6
	"$W/bin/upgradeshim" 6 >/tmp/out 2>&1 && fail 'a bundle signed outside the grant was installed'
	eq "$(cat /etc/ctrlz/versions/node)" 3 'version after a refused upgrade'
	# A symlink where a file should be: never followed.
	mkhub 7
	cp -r /hub/install/bundle/7 /var/lib/ctrlz/bundles/node/7
	rm /var/lib/ctrlz/bundles/node/7/bin/ctrlz-node
	ln -s /etc/shadow /var/lib/ctrlz/bundles/node/7/bin/ctrlz-node
	"$W/bin/upgradeshim" 7 >/tmp/out 2>&1 && fail 'a symlinked file was installed'
	eq "$(cat /etc/ctrlz/versions/node)" 3 'version after a refused upgrade'
	echo "PASS $SCEN"
}

# Stock Ubuntu server images carry systemd-timesyncd, which conflicts with chrony
# (both provide time-daemon). apt runs for real here (the wrapper only injects
# failures), so the install must take timesyncd out in the same transaction that
# brings chrony in, wait for a held dpkg lock, stop with nothing removed when
# another package depends on timesyncd, and leave the host as it was when apt fails
# (p4n-W5c-r5-1 to r5-4, r5-8).
sc_timesyncd() {
	setup_host
	mkhub 3
	mkdeb systemd-timesyncd 255.4 'Provides: time-daemon\nConflicts: time-daemon'
	mkdeb needs-timesyncd 1 'Depends: systemd-timesyncd'
	dpkg -i /tmp/debs/systemd-timesyncd_255.4_all.deb /tmp/debs/needs-timesyncd_1_all.deb >/dev/null 2>&1 || fail 'the stand-ins of the stock host did not install'
	installed() { dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null; }
	# A host with NTP settings of its own: its chrony.conf must survive every failed
	# attempt below.
	mkdir -p /etc/chrony
	printf 'pool ntp.example.invalid iburst\n' >/etc/chrony/chrony.conf
	host_untouched() {
		eq "$(cat /etc/chrony/chrony.conf)" 'pool ntp.example.invalid iburst' "$1: the host chrony.conf"
		[ ! -e /etc/chrony/chrony.conf.ctrlz-orig ] || fail "$1: a copy of the host chrony.conf was left behind"
		eq "$(installed systemd-timesyncd)" installed "$1: timesyncd"
		[ "$(installed chrony)" != installed ] || fail "$1: chrony is installed"
		grep -qE '^systemctl (start|restart|enable) ctrlz' /var/log/stub/calls.log 2>/dev/null && fail "$1: a unit was started"
		grep -q 'systemd-timesyncd' /var/log/stub/calls.log && fail "$1: timesyncd was stopped or disabled"
		[ ! -e /usr/sbin/policy-rc.d ] || fail "$1: policy-rc.d was left behind"
		return 0
	}

	# Another package depends on timesyncd: apt's dry run would remove it too, so the
	# install refuses before anything on the host changed. No mask, no chrony.conf.
	: >/var/log/stub/calls.log
	if run_install >/tmp/out 2>&1; then fail 'the install passed although a package depends on systemd-timesyncd'; fi
	grep -q 'would remove other packages' /tmp/out || fail "no message: $(cat /tmp/out)"
	eq "$(installed needs-timesyncd)" installed 'the dependent package'
	host_untouched 'dependent package'
	grep -q '^systemctl mask' /var/log/stub/calls.log && fail 'a mask was set before the dry run passed'
	dpkg --purge needs-timesyncd >/dev/null 2>&1 || fail 'purge of the dependent'

	# A bundle that does not resolve fails in apt's dry run, with the host unchanged.
	: >/stubcfg/fail-apt-sim
	: >/var/log/stub/calls.log
	if run_install >/tmp/out 2>&1; then fail 'the install passed with an unresolvable bundle'; fi
	grep -q 'do not resolve' /tmp/out || fail 'no message for the failed dry run'
	host_untouched 'failed dry run'
	grep -q '^systemctl mask' /var/log/stub/calls.log && fail 'a mask was set before the dry run passed'
	rm -f /stubcfg/fail-apt-sim

	# The real run fails (a lock that outlasts the timeout): apt changed nothing, so
	# timesyncd is still there, and the chrony.conf and the masks the install put in
	# place for apt are taken away again.
	: >/stubcfg/fail-apt-once
	: >/var/log/stub/calls.log
	if run_install >/tmp/out 2>&1; then fail 'the install passed with a failing apt'; fi
	grep -q 'did not install' /tmp/out || fail 'no message for the failed apt'
	host_untouched 'failed apt'
	grep -q '^systemctl unmask unbound.service' /var/log/stub/calls.log || fail 'the masks were not undone'
	grep -q 'no time daemon' /tmp/out && fail 'a message about a missing time daemon'

	# The dpkg lock is held for a few seconds: apt waits for it, in the same run that
	# removes timesyncd (a purge by hand did not wait, p4n-W5c-r5-3).
	perl -e 'use Fcntl; open(F, ">>", "/var/lib/dpkg/lock-frontend") or die; fcntl(F, F_SETLK, pack("ssx4qqix4", F_WRLCK, 0, 0, 0, 0)) or die "lock: $!"; sleep 6' &
	holder=$!
	sleep 1
	: >/var/log/stub/calls.log
	t0=$(date +%s)
	run_install >/tmp/out 2>&1 || {
		cat /tmp/out
		fail 'install on a host with systemd-timesyncd and a held dpkg lock'
	}
	[ $(($(date +%s) - t0)) -ge 3 ] || fail 'the install did not wait for the dpkg lock (is the lock really held?)'
	wait "$holder" 2>/dev/null
	[ "$(installed systemd-timesyncd)" != installed ] || fail 'systemd-timesyncd is still installed'
	eq "$(installed chrony)" installed 'chrony'
	grep -q 'systemd-timesyncd-' /var/log/stub/apt.log || fail 'timesyncd was not removed in the apt transaction'
	grep -q 'dpkg --purge' /var/log/stub/calls.log && fail 'dpkg --purge was run by hand'
	eq "$(cat /etc/chrony/chrony.conf.ctrlz-orig)" 'pool ntp.example.invalid iburst' 'the host chrony.conf kept as ctrlz-orig'
	grep -q 'stop systemd-timesyncd.service' /var/log/stub/calls.log || fail 'a running timesyncd was not stopped'
	# Nothing but the one package was removed.
	for p in unbound dns-root-data nftables polkitd; do
		eq "$(installed "$p")" installed "package $p"
	done
	echo "PASS $SCEN"
}

# An upgrade that brings a newer unbound package replaces /usr/sbin/unbound, but the
# running ctrlz-unbound keeps the old code; the install restarts a unit whose binary is
# gone from disk and leaves one that runs the current binary (p4n-W5c-r5-7). The
# upgrade also runs through real apt, from an installed older package set.
sc_unbound_restart() {
	setup_host
	mkhub 3
	run_install >/tmp/out 2>&1 || {
		cat /tmp/out
		fail 'install'
	}
	mkhub 4 "$W/bin/verify-lab" 1.20.0-1
	mkdir -p /var/lib/ctrlz/bundles/node
	cp -r /hub/install/bundle/4 /var/lib/ctrlz/bundles/node/4
	chown -R ctrlz-agent:ctrlz /var/lib/ctrlz/bundles
	# Two running "unbound" processes: the identified one runs a binary the upgrade
	# replaced (deleted from disk), the free one a binary still in place.
	# The free one maps a library the upgrade replaced (a copy of a real shared object that
	# is gone from disk); its binary is in place (p4n-W5c-r6-6).
	cp /bin/sleep /tmp/unbound-old
	cp /bin/sleep /tmp/unbound-current
	cp "$(ls /usr/lib/x86_64-linux-gnu/libz.so.1.* | head -1)" /usr/lib/ctrlz-test-lib.so
	/tmp/unbound-old 1000 &
	old=$!
	LD_PRELOAD=/usr/lib/ctrlz-test-lib.so /tmp/unbound-current 1000 &
	cur=$!
	sleep 0.2
	grep -q 'ctrlz-test-lib.so' /proc/$cur/maps || fail 'the stand-in process does not map the library'
	rm -f /tmp/unbound-old /usr/lib/ctrlz-test-lib.so
	echo "$old" >/stubcfg/mainpid.ctrlz-unbound.service
	echo "$cur" >/stubcfg/mainpid.ctrlz-unbound-free.service
	: >/var/log/stub/calls.log
	"$W/bin/upgradeshim" 4 >/tmp/out 2>&1 || {
		cat /tmp/out
		kill "$old" "$cur" 2>/dev/null
		fail 'the upgrade'
	}
	kill "$old" "$cur" 2>/dev/null
	eq "$(dpkg-query -W -f='${Version}' unbound)" 1.20.0-1 'unbound after the upgrade'
	grep -q '^systemctl restart ctrlz-unbound.service' /var/log/stub/calls.log || fail 'the Unbound that runs a replaced binary was not restarted'
	grep -q '^systemctl restart ctrlz-unbound-free.service' /var/log/stub/calls.log || fail 'the Unbound that maps a replaced library was not restarted'
	# Order: the units restart before the agent, so the agent finds the new process.
	r=$(grep -n '^systemctl restart ctrlz-unbound.service' /var/log/stub/calls.log | head -1 | cut -d: -f1)
	a=$(grep -n '^systemctl restart ctrlz-agent' /var/log/stub/calls.log | head -1 | cut -d: -f1)
	[ "$r" -lt "$a" ] || fail 'Unbound was restarted after the agent'

	# Processes that run the current binary and map the current files: not restarted. A deleted
	# mapping that is not a system file (a temporary file, /dev/zero) does not count either.
	mkhub 5 "$W/bin/verify-lab" 1.20.0-1
	cp -r /hub/install/bundle/5 /var/lib/ctrlz/bundles/node/5
	chown -R ctrlz-agent:ctrlz /var/lib/ctrlz/bundles
	cp "$(ls /usr/lib/x86_64-linux-gnu/libz.so.1.* | head -1)" /tmp/ctrlz-test-lib.so
	/tmp/unbound-current 1000 &
	cur2=$!
	LD_PRELOAD=/tmp/ctrlz-test-lib.so /tmp/unbound-current 1000 &
	tmpmap=$!
	sleep 0.2
	rm -f /tmp/ctrlz-test-lib.so
	grep -q 'ctrlz-test-lib.so (deleted)' /proc/$tmpmap/maps || fail 'the stand-in process does not hold a deleted mapping'
	echo "$cur2" >/stubcfg/mainpid.ctrlz-unbound.service
	echo "$tmpmap" >/stubcfg/mainpid.ctrlz-unbound-free.service
	: >/var/log/stub/calls.log
	"$W/bin/upgradeshim" 5 >/tmp/out 2>&1 || {
		cat /tmp/out
		kill "$cur2" "$tmpmap" 2>/dev/null
		fail 'the second upgrade'
	}
	kill "$cur2" "$tmpmap" 2>/dev/null
	grep -q '^systemctl restart ctrlz-unbound' /var/log/stub/calls.log && fail 'an Unbound with only current system files was restarted'
	echo "PASS $SCEN"
}

# The agent owns /var/lib/ctrlz, so it can put a symbolic link where a directory or a
# key file is. Root runs chown, chmod and install over those paths during an upgrade
# and a repeat install (7.1, R16): none may follow the link.
sc_planted_links() {
	setup_host
	mkhub 3
	run_install >/tmp/out 2>&1 || {
		cat /tmp/out
		fail 'install'
	}
	# The packages are installed; the rest of this scenario repeats refused upgrades and installs, which
	# would run the dpkg work in every one of them for nothing.
	: >/stubcfg/apt-noop
	mkhub 4 "$W/bin/verify-lab" 1.20.0-1
	mkdir -p /var/lib/ctrlz/bundles/node
	cp -r /hub/install/bundle/4 /var/lib/ctrlz/bundles/node/4
	chown -R ctrlz-agent:ctrlz /var/lib/ctrlz/bundles
	mkdir -p /victims
	snap() { stat -c '%U:%G %a %s' "$1"; }

	node_before=$(cat /usr/local/bin/ctrlz-node)
	for d in /var/lib/ctrlz /var/lib/ctrlz/state /var/lib/ctrlz/log /var/lib/ctrlz/blobs /var/lib/ctrlz/quarantine \
		/var/lib/ctrlz/image /var/lib/ctrlz/push /var/lib/ctrlz/keys /var/lib/ctrlz/config /var/lib/ctrlz/bundles \
		/etc/ctrlz/unbound /etc/ctrlz/chrony; do
		v=/victims/$(echo "$d" | tr / _)
		mkdir -p "$v"
		chown root:root "$v"
		chmod 0755 "$v"
		before=$(snap "$v")
		mv "$d" "$d.real"
		ln -s "$v" "$d"
		# The upgrade (the real code, the root-owned verifier, apply.sh) ...
		"$W/bin/upgradeshim" 4 >/tmp/out 2>&1 && fail "an upgrade ran with $d a symbolic link"
		eq "$(snap "$v")" "$before" "target of the link at $d after an upgrade"
		# ... and a repeat install.
		run_install >/tmp/out 2>&1 && fail "a repeat install ran with $d a symbolic link"
		eq "$(snap "$v")" "$before" "target of the link at $d after an install"
		eq "$(cat /usr/local/bin/ctrlz-node)" "$node_before" "the binary changed with $d a link"
		eq "$(cat /etc/ctrlz/versions/node)" 3 "recorded version with $d a link"
		rm "$d"
		mv "$d.real" "$d"
	done

	# A link in the place of a key file: the install replaces the link and never
	# writes through it.
	K=/var/lib/ctrlz/keys
	for f in hub.pin root.json node_ca.pem enroll.token node.key node.crt enroll.pending; do
		printf 'precious %s\n' "$f" >"/victims/file-$f"
		chmod 0644 "/victims/file-$f"
		chown root:root "/victims/file-$f"
		rm -f "$K/$f"
		ln -s "/victims/file-$f" "$K/$f"
	done
	before=$(for f in hub.pin root.json node_ca.pem enroll.token node.key node.crt enroll.pending; do snap "/victims/file-$f"; cat "/victims/file-$f"; done)
	run_install >/tmp/out 2>&1 || {
		cat /tmp/out
		fail 'a repeat install over planted key links'
	}
	after=$(for f in hub.pin root.json node_ca.pem enroll.token node.key node.crt enroll.pending; do snap "/victims/file-$f"; cat "/victims/file-$f"; done)
	eq "$after" "$before" 'files the planted key links pointed at'
	for f in hub.pin root.json node_ca.pem enroll.token; do
		[ -f "$K/$f" ] && [ ! -L "$K/$f" ] || fail "keys/$f is not a regular file after the install"
	done
	eq "$(cat $K/hub.pin)" "$PIN" 'keys/hub.pin'
	echo "PASS $SCEN"
}

# A unit that does not stop: the agent could still write the tree, so root does
# not touch it.
sc_agent_running() {
	setup_host
	mkhub 3
	run_install >/tmp/out 2>&1 || fail 'install'
	mkhub 4 "$W/bin/verify-lab" 1.20.0-1
	mkdir -p /var/lib/ctrlz/bundles/node
	cp -r /hub/install/bundle/4 /var/lib/ctrlz/bundles/node/4
	chown -R ctrlz-agent:ctrlz /var/lib/ctrlz/bundles
	before=$(cat /usr/local/bin/ctrlz-node)
	for u in ctrlz-agent.service ctrlz-dns.service ctrlz-proxy.service; do
		echo "$u" >/stubcfg/active
		: >/var/log/stub/calls.log
		"$W/bin/upgradeshim" 4 >/tmp/out 2>&1 && fail "an upgrade ran with $u still active"
		grep -q 'still running' /tmp/out || fail "no message for $u"
		eq "$(cat /usr/local/bin/ctrlz-node)" "$before" "binary with $u active"
		eq "$(cat /etc/ctrlz/versions/node)" 3 "version with $u active"
		grep -qE '^systemctl (start|restart|enable)' /var/log/stub/calls.log && fail "a unit was started with $u active"
	done
	rm -f /stubcfg/active
	echo "PASS $SCEN"
}

# drop_accounts removes what a refused install already made, so the next case starts clean.
drop_accounts() {
	for u in intruder ctrlz-agent ctrlz-dns ctrlz-proxy ctrlz-unbound ctrlz-unbound-free; do userdel "$u" >/dev/null 2>&1; done
	for g in ctrlz ctrlz-agent ctrlz-dns ctrlz-proxy ctrlz-unbound ctrlz-unbound-free ctrlz-unbound-cfg; do groupdel "$g" >/dev/null 2>&1; done
	return 0
}

# Accounts that exist already must be what accounts.conf says, and no other account
# may have a declared group as its primary group (that is not in the member list).
sc_account_drift() {
	setup_host
	mkhub 3
	groupadd --system ctrlz
	useradd --system -M -s /usr/sbin/nologin -g ctrlz intruder
	if run_install >/tmp/out 2>&1; then fail 'the install passed with an account whose primary group is ctrlz'; fi
	grep -q 'primary group of' /tmp/out || fail 'no message for the primary group'
	grep -qE '^systemctl (start|restart|enable)' /var/log/stub/calls.log 2>/dev/null && fail 'a unit was started'
	drop_accounts

	# A declared account that exists with a shell.
	groupadd --system ctrlz-dns
	useradd --system -M -s /bin/sh -g ctrlz-dns ctrlz-dns
	if run_install >/tmp/out 2>&1; then fail 'the install passed with ctrlz-dns having a shell'; fi
	grep -q 'has a shell' /tmp/out || fail 'no message for the shell'
	drop_accounts

	# A declared account with another primary group.
	groupadd --system ctrlz-agent
	useradd --system -M -s /usr/sbin/nologin -g nogroup ctrlz-agent
	if run_install >/tmp/out 2>&1; then fail 'the install passed with ctrlz-agent in another primary group'; fi
	grep -q 'another primary group' /tmp/out || fail 'no message for the primary group of a declared user'
	[ ! -e /usr/local/bin/ctrlz-node ] || fail 'the binary was installed'
	drop_accounts

	# A declared account that belongs to a group outside accounts.conf (docker would
	# hand a compromised agent root through a socket it can still reach).
	groupadd docker
	groupadd --system ctrlz-dns
	useradd --system -M -s /usr/sbin/nologin -g ctrlz-dns -G docker ctrlz-dns
	if run_install >/tmp/out 2>&1; then fail 'the install passed with ctrlz-dns in the docker group'; fi
	grep -q 'is in the groups' /tmp/out || fail "no message for a group outside accounts.conf: $(cat /tmp/out)"
	[ ! -e /usr/local/bin/ctrlz-node ] || fail 'the binary was installed with a docker member'
	drop_accounts
	groupdel docker

	# A declared account with UID 0 (systemd skips polkit for root).
	groupadd --system ctrlz-agent
	useradd -o -u 0 -M -s /usr/sbin/nologin -g ctrlz-agent ctrlz-agent
	if run_install >/tmp/out 2>&1; then fail 'the install passed with a UID 0 ctrlz-agent'; fi
	grep -q 'outside the system range' /tmp/out || fail "no message for UID 0: $(cat /tmp/out)"
	[ ! -e /usr/local/bin/ctrlz-node ] || fail 'the binary was installed with a UID 0 agent'
	echo "PASS $SCEN"
}


# An upgrade that fails must not leave the node down (p4n-W5c-r3-1). apt fails before
# anything is stopped; a later step (sysctl) fails after the stop, and the units that
# were running are started again.
sc_upgrade_failure() {
	setup_host
	mkhub 3
	run_install >/tmp/out 2>&1 || {
		cat /tmp/out
		fail 'install'
	}
	mkhub 4 "$W/bin/verify-lab" 1.20.0-1
	mkdir -p /var/lib/ctrlz/bundles/node
	cp -r /hub/install/bundle/4 /var/lib/ctrlz/bundles/node/4
	chown -R ctrlz-agent:ctrlz /var/lib/ctrlz/bundles
	printf '%s\n' ctrlz-agent.service ctrlz-dns.service ctrlz-proxy.service >/stubcfg/running
	running_all() {
		for u in ctrlz-agent.service ctrlz-dns.service ctrlz-proxy.service; do
			grep -qxF "$u" /stubcfg/running || fail "$1: $u is not running"
		done
	}

	# apt cannot run (a held dpkg lock past the timeout, a package that does not
	# resolve): the services were never stopped.
	: >/stubcfg/fail-apt
	: >/var/log/stub/calls.log
	rm -f /var/log/stub/apt.state
	"$W/bin/upgradeshim" 4 >/tmp/out 2>&1 && fail 'an upgrade passed with apt failing'
	grep -q 'did not install' /tmp/out || fail 'no message for the failed apt'
	grep -q '^systemctl stop' /var/log/stub/calls.log && fail 'a unit was stopped before apt had run'
	running_all 'after a failed apt'
	eq "$(cat /etc/ctrlz/versions/node)" 3 'version after a failed apt'
	grep -q 'DPkg::Lock::Timeout=300' /var/log/stub/apt.log || fail 'apt does not wait for the dpkg lock'
	# While apt ran: no service may start, the node's chrony.conf was in place, the
	# distribution's Unbound was masked; afterwards policy-rc.d is gone.
	grep -qx 'policy-rc.d exit 101' /var/log/stub/apt.state || fail 'policy-rc.d did not forbid starts during apt'
	# The marked file the install wrote expires on its own: if the script were killed
	# (SIGKILL, power cut) the file would stay, and after an hour it must stop
	# forbidding (p4n-W5c-r4-5). Its stamp is rewritten to an old one here.
	[ -f /var/log/stub/policy-rc.d.copy ] || fail 'no copy of the policy-rc.d the install wrote'
	cp /var/log/stub/policy-rc.d.copy /tmp/prc-fresh
	sed 's/ - [0-9][0-9]* ))/ - 1000000000 ))/' /var/log/stub/policy-rc.d.copy >/tmp/prc-old
	chmod 0755 /tmp/prc-fresh /tmp/prc-old
	grep -q -- '- 1000000000 ))' /tmp/prc-old || fail 'the policy-rc.d carries no stamp'
	/tmp/prc-fresh chrony start
	eq "$?" 101 'a fresh policy-rc.d'
	/tmp/prc-old chrony start
	eq "$?" 0 'an expired policy-rc.d'
	grep -qx 'chrony.conf ours' /var/log/stub/apt.state || fail 'the node chrony.conf was not in place before apt'
	grep -qx 'unbound masked' /var/log/stub/apt.state || fail 'the distribution Unbound was not masked before apt'
	[ ! -e /usr/sbin/policy-rc.d ] || fail 'policy-rc.d was left behind after a failed apt'
	rm -f /stubcfg/fail-apt

	# A step after the stop fails: the units come back, and nothing is half-recorded.
	: >/stubcfg/fail-sysctl
	: >/var/log/stub/calls.log
	"$W/bin/upgradeshim" 4 >/tmp/out 2>&1 && fail 'an upgrade passed with sysctl failing'
	grep -q '^systemctl stop' /var/log/stub/calls.log || fail 'the units were not stopped before the failing step'
	running_all 'after a failed sysctl'
	eq "$(cat /etc/ctrlz/versions/node)" 3 'version after a failed sysctl'
	[ ! -e /usr/sbin/policy-rc.d ] || fail 'policy-rc.d was left behind'
	rm -f /stubcfg/fail-sysctl

	# And the upgrade then goes through.
	"$W/bin/upgradeshim" 4 >/tmp/out 2>&1 || {
		cat /tmp/out
		fail 'the upgrade after the failures'
	}
	eq "$(cat /etc/ctrlz/versions/node)" 4 'version after the upgrade'
	running_all 'after the upgrade'
	rm -f /stubcfg/running
	echo "PASS $SCEN"
}

# The host's own apt took a newer unbound than the bundle carries: the upgrade keeps it
# and does not hand apt the older package (p4n-W5c-r3-2). An administrator's own
# policy-rc.d comes back (the node's is only there while apt runs).
sc_newer_package() {
	setup_host
	mkhub 3 "$W/bin/verify-lab" 1.20.0-1
	run_install >/tmp/out 2>&1 || {
		cat /tmp/out
		fail 'install'
	}
	eq "$(dpkg-query -W -f='${Version}' unbound)" 1.20.0-1 'unbound after the install'
	mkhub 4 "$W/bin/verify-lab" 1.19.2-1ubuntu3.1
	mkdir -p /var/lib/ctrlz/bundles/node
	cp -r /hub/install/bundle/4 /var/lib/ctrlz/bundles/node/4
	chown -R ctrlz-agent:ctrlz /var/lib/ctrlz/bundles
	printf '#!/bin/sh\n# the administrator'"'"'s own\nexit 0\n' >/usr/sbin/policy-rc.d
	chmod 0755 /usr/sbin/policy-rc.d
	: >/var/log/stub/apt.log
	"$W/bin/upgradeshim" 4 >/tmp/out 2>&1 || {
		cat /tmp/out
		fail 'the upgrade with a newer installed package'
	}
	grep -q 'unbound_' /var/log/stub/apt.log && fail 'apt was handed the older unbound'
	grep -q 'chrony_' /var/log/stub/apt.log || fail 'the other packages were not passed to apt'
	eq "$(dpkg-query -W -f='${Version}' unbound)" 1.20.0-1 'unbound after the upgrade'
	eq "$(cat /etc/ctrlz/versions/node)" 4 'version after the upgrade'
	grep -q "the administrator's own" /usr/sbin/policy-rc.d || fail "the administrator's policy-rc.d was not restored"
	[ ! -e /usr/sbin/policy-rc.d.ctrlz-saved ] || fail 'the saved policy-rc.d was left behind'
	echo "PASS $SCEN"
}

# Every bundle file is fetched with the size the signed manifest lists as its limit,
# not the global cap (p4n-W5c-r2-1, r2-6).
check_download_bounds() {
	"$W/bin/verify-lab" sizes --root /hub/install/root.json --manifest "/hub/install/bundle/$1/manifest.json" --version "$1" >/tmp/sizes || fail 'sizes of the bundle'
	[ -s /tmp/sizes ] || fail 'the bundle lists no file'
	while read -r sz p; do
		[ "$sz" != 0 ] || sz=1
		grep -q -- "--max-filesize $sz .*/install/bundle/$1/$p\$" /var/log/stub/curl.args || fail "the download of $p is not bounded by its listed size $sz"
	done </tmp/sizes
}

# A hub under the pin that serves more bytes than the manifest lists is cut off by
# the download bound, before ctrlz-verify check and before anything is installed.
sc_oversized() {
	setup_host
	mkhub 3
	f=/hub/install/bundle/3/bin/ctrlz-node
	head -c 1048576 /dev/zero >>"$f"
	if run_install >/tmp/out 2>&1; then fail 'an oversized bundle file installed'; fi
	grep -q 'fetching /install/bundle/3/bin/ctrlz-node failed' /tmp/out || fail "the download was not cut off by its bound: $(cat /tmp/out)"
	grep -q 'bin/ctrlz-node' /var/log/stub/refused-size.log || fail 'curl did not refuse the oversized body'
	ls /var/tmp/ctrlz-install.* >/dev/null 2>&1 && fail 'the oversized download was left on disk'
	nothing_installed 'oversized file'
	no_leak 'oversized file'
	echo "PASS $SCEN"
}

# Host quirks the container cannot have by itself (p4n-W5c-r2-2, r2-5): a host where
# AppArmor is not in force but apparmor_parser is installed, and a stock Ubuntu Server
# with apport.
sc_host_quirks() {
	setup_host
	mkhub 3
	# apparmor_parser is there and fails, as it can where the LSM is off; aa-enabled says so.
	printf '#!/bin/sh\necho "$0 $*" >>/var/log/stub/apparmor.log\nexit 1\n' >/usr/local/bin/apparmor_parser
	printf '#!/bin/sh\nexit 1\n' >/usr/local/bin/aa-enabled
	chmod 0755 /usr/local/bin/apparmor_parser /usr/local/bin/aa-enabled
	mkdir -p /etc/apparmor.d /usr/lib/systemd/system
	: >/etc/apparmor.d/usr.sbin.unbound
	: >/etc/apparmor.d/usr.sbin.chronyd
	printf '[Service]\nExecStart=/bin/true\n' >/usr/lib/systemd/system/apport.service
	run_install >/tmp/out 2>&1 || {
		cat /tmp/out
		fail 'the install stopped on a host without AppArmor'
	}
	[ ! -e /var/log/stub/apparmor.log ] || fail 'apparmor_parser ran where AppArmor is not in force'
	grep -q '^systemctl disable --now apport.service' /var/log/stub/calls.log || fail 'apport was not stopped'
	grep -q '^systemctl mask apport.service' /var/log/stub/calls.log || fail 'apport was not masked'
	grep -q '^kernel.core_pattern = |/usr/lib/systemd/systemd-coredump ' /etc/sysctl.d/60-ctrlz.conf || fail 'the core pattern is not set'
	grep -q '^sysctl -p /etc/sysctl.d/60-ctrlz.conf' /var/log/stub/calls.log || fail 'the sysctl file was not applied'

	# Where AppArmor is in force, a profile that does not load still stops the install.
	printf '#!/bin/sh\nexit 0\n' >/usr/local/bin/aa-enabled
	if run_install >/tmp/out2 2>&1; then fail 'a failing profile reload was ignored where AppArmor is in force'; fi
	grep -q 'did not reload' /tmp/out2 || fail 'no message for the profile reload'
	[ -s /var/log/stub/apparmor.log ] || fail 'apparmor_parser did not run where AppArmor is in force'
	echo "PASS $SCEN"
}

# apt's configuration on the host may set APT::Get::Purge: the dry run then prints Purg and
# not Remv, and the check of what would go away must still see it (p4n-W5c-r6-4).
sc_apt_purge() {
	setup_host
	mkhub 3
	mkdeb other-timed 1 'Provides: time-daemon\nConflicts: time-daemon'
	dpkg -i /tmp/debs/other-timed_1_all.deb >/dev/null 2>&1 || fail 'the stand-in time daemon did not install'
	mkdir -p /etc/apt/apt.conf.d
	printf 'APT::Get::Purge "true";\n' >/etc/apt/apt.conf.d/99-purge
	if run_install >/tmp/out 2>&1; then
		cat /tmp/out
		fail 'the install passed although it would purge another time daemon'
	fi
	grep -q 'would remove other packages' /tmp/out || fail "no message: $(cat /tmp/out)"
	eq "$(dpkg-query -W -f='${db:Status-Status}' other-timed 2>/dev/null)" installed 'the other time daemon'
	[ ! -e /usr/sbin/policy-rc.d ] || fail 'policy-rc.d was left behind'
	echo "PASS $SCEN"
}

# apt does its work and still ends in an error: unbound is configured, and only the mask
# keeps its unit off. The failure must not undo the masks or the node's chrony.conf; the
# run can be repeated (p4n-W5c-r6-5).
sc_apt_partial() {
	setup_host
	mkhub 3
	mkdir -p /etc/chrony
	printf 'pool ntp.example.invalid iburst\n' >/etc/chrony/chrony.conf
	: >/stubcfg/fail-apt-after
	: >/var/log/stub/calls.log
	if run_install >/tmp/out 2>&1; then fail 'the install passed with a failing apt'; fi
	eq "$(dpkg-query -W -f='${db:Status-Status}' unbound 2>/dev/null)" installed 'unbound after the failed run'
	grep -q '^systemctl unmask' /var/log/stub/calls.log && fail 'a mask of the distribution Unbound was removed while the package is installed'
	grep -q '^confdir /etc/ctrlz/chrony' /etc/chrony/chrony.conf || fail 'the node chrony.conf was replaced by the host file while chrony is installed'
	eq "$(cat /etc/chrony/chrony.conf.ctrlz-orig)" 'pool ntp.example.invalid iburst' 'the host chrony.conf kept as ctrlz-orig'
	[ ! -e /usr/sbin/policy-rc.d ] || fail 'policy-rc.d was left behind'
	grep -qE '^systemctl (start|restart|enable) ctrlz' /var/log/stub/calls.log && fail 'a unit was started'
	: >/var/log/stub/calls.log
	run_install >/tmp/out 2>&1 || {
		cat /tmp/out
		fail 'the repeated install'
	}
	eq "$(cat /etc/chrony/chrony.conf.ctrlz-orig)" 'pool ntp.example.invalid iburst' 'ctrlz-orig after the repeat'
	echo "PASS $SCEN"
}

case $SCEN in
happy) sc_happy ;;
apt-purge) sc_apt_purge ;;
apt-partial) sc_apt_partial ;;
os-release) sc_os_release ;;
wrong-root) sc_wrong_root ;;
wrong-verify) sc_wrong_verify ;;
wrong-script) sc_wrong_script ;;
outside-grant) sc_outside_grant ;;
one-signature) sc_one_signature ;;
file-tampered) sc_file_tampered ;;
file-not-listed) sc_file_not_listed ;;
lab-root-in-production) sc_lab_root_in_production ;;
old-unbound) sc_old_unbound ;;
group-drift) sc_group_drift ;;
token-arguments) sc_token_arguments ;;
bad-addresses) sc_bad_addresses ;;
upgrade) sc_upgrade ;;
upgrade-tampered) sc_upgrade_tampered ;;
timesyncd) sc_timesyncd ;;
unbound-restart) sc_unbound_restart ;;
planted-links) sc_planted_links ;;
agent-running) sc_agent_running ;;
account-drift) sc_account_drift ;;
oversized) sc_oversized ;;
host-quirks) sc_host_quirks ;;
upgrade-failure) sc_upgrade_failure ;;
newer-package) sc_newer_package ;;
*)
	echo "unknown scenario" >&2
	exit 2
	;;
esac
