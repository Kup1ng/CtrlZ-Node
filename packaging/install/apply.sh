#!/bin/sh
# apply.sh installs a node bundle that ctrlz-verify has already verified
# (p4-nodes 4.2 step 2, 7.1). Two callers run it, and nobody else:
#
#   node.sh                  apply.sh install --stage DIR --version N ...   (first install)
#   ctrlz-node upgrade       apply.sh upgrade --stage DIR --version N       (root one-shot)
#
# Both hand it a root-owned staging directory whose every file matched the signed
# manifest. The script is in the bundle, so it is itself under the signature, and
# it is the one place the install steps live: an upgrade is an install that keeps
# the host's identity and configuration.
#
# What it must never do: reach the network (apt's package sources are switched
# off and curl is not used), run anything it did not get from the staging
# directory, or let the agent account install anything. It writes only where the
# lists next to it (accounts.conf, dirs.conf, files.conf) say.
set -eu
umask 022
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# The oldest Ubuntu 24.04 unbound revision that carries the DNSBomb fix; the agent
# applies the same floor when it starts Unbound (p4-nodes 7.3). A newer revision or
# a newer upstream passes. P6 re-confirms the pin against later advisories.
UNBOUND_FLOOR='1.19.2-1ubuntu3.1'

die() {
	printf 'ctrlz-install: %s\n' "$*" >&2
	exit 1
}

# The services that were running when the script began, and the policy-rc.d it put in
# place. cleanup runs on every exit: it takes the policy-rc.d away, and when the
# script failed it starts again each service it had stopped. Without that a failed
# upgrade (a full disk, a failed sysctl, a refused profile reload) would leave a
# node that served DNS with no DNS and no agent until someone noticed, because the
# units were stopped by hand and systemd's Restart= does not undo that.
WAS_ACTIVE=
PRC=/usr/sbin/policy-rc.d
PRC_MARK='# ctrlz-install: no service starts while the packages install'

release_services() {
	if [ -f "$PRC" ] && grep -qF "$PRC_MARK" "$PRC" 2>/dev/null; then
		rm -f "$PRC"
	fi
	if [ ! -e "$PRC" ] && [ -e "$PRC.ctrlz-saved" ]; then
		mv "$PRC.ctrlz-saved" "$PRC"
	fi
	return 0
}

# apt never reads a package source: only the bundle's own .deb files are installed
# (T-359). With no source list apt has no index to download from, so no --no-download
# is needed; real apt refuses that flag together with local .deb files.
#
# Purge and AutomaticRemove are pinned off: an administrator's apt.conf.d may set
# APT::Get::Purge, and then the dry run prints "Purg <pkg>" and not "Remv <pkg>", so the
# check of what would be removed (apply_packages) saw nothing while the real run purged
# the package and its configuration (p4n-W5c-r6-4). AutomaticRemove would take packages
# the bundle never named.
APT_OPTS="-o Dir::Etc::sourcelist=/dev/null -o Dir::Etc::sourceparts=/dev/null -o APT::Get::Purge=false -o APT::Get::AutomaticRemove=false"

# What apply_packages changed before apt ran, so a failed apt can put it back: the
# host's own chrony.conf and the masks on the distribution's Unbound units. PRE_APT is 1
# from the first of those changes until apt has succeeded. The time daemon needs no
# such care: systemd-timesyncd goes out in the same apt transaction that brings chrony
# in, so a transaction that fails leaves it installed (p4n-W5c-r5-2, r5-8).
PRE_APT=0
CHRONY_PREV=
CHRONY_ORIG_NEW=0
CHRONY_WAS_HERE=
UNBOUND_WAS_HERE=
MASKED_BY_US=

# pkg_here PKG: dpkg holds files of the package (installed, unpacked or half-configured),
# as opposed to never seen, removed or only its configuration kept.
pkg_here() {
	case $(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null) in '' | not-installed | config-files) return 1 ;; esac
	return 0
}

revert_pre_apt() {
	[ "$PRE_APT" = 1 ] || return 0
	PRE_APT=0
	# A failed dpkg transaction can leave a package configured: its postinst ran, and
	# for unbound that enabled unbound.service, which only the mask keeps off. So what
	# apt brought in is judged by the package state now, not by the exit code: a package
	# this run added keeps the node's chrony.conf and the masks, and only a host where
	# apt changed nothing gets its own file and units back (p4n-W5c-r6-5).
	if pkg_here chrony && [ -z "$CHRONY_WAS_HERE" ]; then
		:
	elif [ "$CHRONY_PREV" = none ]; then
		rm -f /etc/chrony/chrony.conf
	elif [ -n "$CHRONY_PREV" ] && [ -f "$CHRONY_PREV" ]; then
		mv -f "$CHRONY_PREV" /etc/chrony/chrony.conf
		[ "$CHRONY_ORIG_NEW" = 0 ] || rm -f /etc/chrony/chrony.conf.ctrlz-orig
	fi
	if pkg_here unbound && [ -z "$UNBOUND_WAS_HERE" ]; then
		return 0
	fi
	for u in $MASKED_BY_US; do
		systemctl unmask "$u" >/dev/null 2>&1 || true
	done
	return 0
}

cleanup() {
	rc=$?
	trap - EXIT
	# A second signal (Ctrl-C and the forwarded TERM of ctrlz-node upgrade arrive together)
	# must not cut this short: it is what starts the stopped units again.
	trap '' HUP INT TERM
	release_services || true
	[ "$rc" -eq 0 ] || revert_pre_apt || true
	if [ "$rc" -ne 0 ]; then
		for u in $WAS_ACTIVE; do
			systemctl is-active --quiet "$u" >/dev/null 2>&1 || systemctl start "$u" >/dev/null 2>&1 || true
		done
	fi
	exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

[ "$(id -u)" = 0 ] || die 'must run as root'
[ $# -ge 1 ] || die 'usage: apply.sh install|upgrade --stage DIR --version N [options]'
MODE=$1
shift
case $MODE in install | upgrade) ;; *) die "unknown mode" ;; esac

STAGE=
VERSION=
HUB=
PIN=
ROOT_JSON=
NODE_CA=
TOKEN_FILE=
DNS_BIND=
DNS_ADV=
PROXY_BIND=
PROXY_ADV=
FREE_OUT=
PANEL_ADDRS=

while [ $# -gt 0 ]; do
	[ $# -ge 2 ] || die "option $1 needs a value"
	case $1 in
	--stage) STAGE=$2 ;;
	--version) VERSION=$2 ;;
	--hub) HUB=$2 ;;
	--pin) PIN=$2 ;;
	--root-json) ROOT_JSON=$2 ;;
	--node-ca) NODE_CA=$2 ;;
	--enroll-token-file) TOKEN_FILE=$2 ;;
	--dns-bind-ip) DNS_BIND=$2 ;;
	--dns-advertised-ip) DNS_ADV=$2 ;;
	--proxy-bind-ip) PROXY_BIND=$2 ;;
	--proxy-advertised-ip) PROXY_ADV=$2 ;;
	--free-outgoing-ip) FREE_OUT=$2 ;;
	--panel-addrs) PANEL_ADDRS=$2 ;;
	*) die "unknown option" ;;
	esac
	shift 2
done

[ -d "$STAGE" ] || die 'no staging directory'
# apt installs a local file only by an absolute path.
case $STAGE in /*) ;; *) die 'the staging directory must be an absolute path' ;; esac
case $VERSION in '' | *[!0-9]*) die 'bad version' ;; esac
for f in accounts.conf dirs.conf files.conf; do
	[ -f "$STAGE/packaging/$f" ] || die "the bundle has no packaging/$f"
done

# is_ip: an address by its characters only. agent.conf is parsed strictly by the
# agent, but a value with a newline or a space must never reach it from here.
is_ip() {
	case $1 in '' | *[!0-9a-fA-F:.]*) return 1 ;; esac
	case $1 in *.* | *:*) return 0 ;; esac
	return 1
}

# check_addrs VERIFIER: the addresses by what the agent will accept (ctrlz-verify addr),
# not by characters: "10.0.0.256", "1.2.3" and "0.0.0.0" pass is_ip, and an install that
# wrote them would report success for a node whose agent then refuses its own
# agent.conf on every start (p4n-W5c-r6-3). agent.conf splits panel_addrs on commas, so
# an empty element is refused here too, where the shell would drop it.
check_addrs() {
	case $PANEL_ADDRS in , | ,* | *, | *,,*) die 'bad --panel-addrs' ;; esac
	_v=$1
	shift
	set -- "$DNS_BIND" "$DNS_ADV" "$PROXY_BIND" "$PROXY_ADV"
	[ -z "$FREE_OUT" ] || set -- "$@" "$FREE_OUT"
	if [ -n "$PANEL_ADDRS" ]; then
		_ifs=$IFS
		IFS=,
		# The characters were checked above: no glob and no space can be in the value.
		# shellcheck disable=SC2086
		set -- "$@" $PANEL_ADDRS
		IFS=$_ifs
	fi
	"$_v" addr "$@" || die 'an address is not one the node can run with (--dns-bind-ip, --dns-advertised-ip, --proxy-bind-ip, --proxy-advertised-ip, --free-outgoing-ip, --panel-addrs)'
}

if [ "$MODE" = install ]; then
	[ -n "$HUB" ] && [ -n "$PIN" ] && [ -f "$ROOT_JSON" ] && [ -f "$NODE_CA" ] || die 'install needs --hub, --pin, --root-json and --node-ca'
	# In a bracket expression the "]" comes first and the "[" and "-" are literal.
	case $HUB in *[!]0-9A-Za-z.:[-]*) die 'bad hub' ;; esac
	case $PIN in sha256//*) ;; *) die 'bad pin' ;; esac
	case ${PIN#sha256//} in '' | *[!A-Za-z0-9+/=]*) die 'bad pin' ;; esac
	[ -z "$DNS_ADV" ] && DNS_ADV=$DNS_BIND
	[ -z "$PROXY_ADV" ] && PROXY_ADV=$PROXY_BIND
	for a in "$DNS_BIND" "$DNS_ADV" "$PROXY_BIND" "$PROXY_ADV"; do
		is_ip "$a" || die 'the four addresses must be IP addresses'
	done
	[ -z "$FREE_OUT" ] || is_ip "$FREE_OUT" || die 'bad --free-outgoing-ip'
	case $PANEL_ADDRS in *[!0-9a-fA-F:.,]*) die 'bad --panel-addrs' ;; esac
	# The staged verifier is the one node.sh checked against the manifest and its stamped
	# hash. Files come out of the download without an execute bit, so a copy is run.
	cp "$STAGE/bin/ctrlz-verify" "$STAGE/ctrlz-verify.run" && chmod 0700 "$STAGE/ctrlz-verify.run" || die 'the verifier cannot be prepared'
	check_addrs "$STAGE/ctrlz-verify.run"
	rm -f "$STAGE/ctrlz-verify.run"
fi

# --- the agent's tree is not trusted ------------------------------------------------
# ctrlz-agent owns /var/lib/ctrlz and the two directories under /etc/ctrlz it writes
# to, so it can rename any child of them and put a symbolic link in its place. Root
# runs chown, chmod, rm and install on those paths below, and each of them would
# follow such a link to wherever the agent pointed it (an upgrade is routine, so a
# compromised agent only has to wait). Two defences, both needed:
#   1. the services that run as the agent are stopped first, so nothing can change
#      the tree while this script works in it;
#   2. every path of dirs.conf must be a real directory and not a link, before this
#      script changes anything; the file writes below remove their target first.
# The services are started again by apply_services, or by cleanup when a step fails.
# Everything that only reads or installs packages (accounts, apt, the version floor)
# runs before quiesce, so the usual ways an upgrade fails (a held dpkg lock, a
# package that does not resolve) leave the node as it was.
quiesce() {
	for u in ctrlz-agent.service ctrlz-dns.service ctrlz-proxy.service; do
		if systemctl is-active --quiet "$u" >/dev/null 2>&1; then
			WAS_ACTIVE="$WAS_ACTIVE $u"
		fi
	done
	systemctl stop ctrlz-agent.service ctrlz-dns.service ctrlz-proxy.service >/dev/null 2>&1 || true
	for u in ctrlz-agent.service ctrlz-dns.service ctrlz-proxy.service; do
		if systemctl is-active --quiet "$u" >/dev/null 2>&1; then
			die "$u is still running; stop it before the install"
		fi
	done
}

# plain_dirs refuses a link, or anything that is not a directory, where dirs.conf
# names a directory. A path that does not exist yet is made later, by root.
plain_dirs() {
	while read -r path _; do
		case $path in '' | '#'*) continue ;; esac
		[ ! -L "$path" ] || die "$path is a symbolic link; refusing to follow it"
		if [ -e "$path" ] && [ ! -d "$path" ]; then die "$path is not a directory"; fi
	done <"$STAGE/packaging/dirs.conf"
}

# --- accounts ---------------------------------------------------------------------
# Groups, then users, then memberships, in the order of accounts.conf. A user or
# group that exists is kept; the membership of every declared group is then
# compared with the list, because "group ctrlz holds only dns and agent" is a
# property of the host, not of what this script added.
apply_accounts() {
	while read -r kind a b c _; do
		case $kind in '' | '#'*) continue ;; esac
		case $kind in
		group) getent group "$a" >/dev/null || groupadd --system "$a" ;;
		user)
			getent passwd "$a" >/dev/null ||
				useradd --system --no-create-home --home-dir "$c" --shell /usr/sbin/nologin --gid "$b" "$a"
			;;
		member) id -nG "$a" | tr ' ' '\n' | grep -qx "$b" || usermod -aG "$b" "$a" ;;
		*) die "accounts.conf: unknown line" ;;
		esac
	done <"$STAGE/packaging/accounts.conf"

	grep -E '^group ' "$STAGE/packaging/accounts.conf" | while read -r _ g; do
		want=$(grep -E "^member [^ ]+ $g\$" "$STAGE/packaging/accounts.conf" | cut -d' ' -f2 | sort | tr '\n' ',')
		have=$(getent group "$g" | cut -d: -f4 | tr ',' '\n' | grep -v '^$' | sort | tr '\n' ',')
		[ "$want" = "$have" ] || die "group $g has members '$have', expected '$want'"
	done

	# A kept account must be what accounts.conf says: its primary group and a shell
	# that cannot log in. And no other account may have a declared group as its
	# primary group: that is not in the member list of field 4 of /etc/group, yet it
	# has the group's whole access (agent.sock, the group-readable store).
	while read -r kind a b _; do
		[ "$kind" = user ] || continue
		ent=$(getent passwd "$a") || die "user $a is missing"
		[ "$(printf '%s' "$ent" | cut -d: -f4)" = "$(getent group "$b" | cut -d: -f3)" ] || die "user $a has another primary group than $b"
		[ "$(printf '%s' "$ent" | cut -d: -f7)" = /usr/sbin/nologin ] || die "user $a has a shell"
		# A system UID, never 0 (systemd does not ask polkit about root, so a UID 0 agent
		# could run every unit action), and no group beyond the declared ones (docker or
		# lxd would hand a compromised agent root through a socket it can still reach).
		uid=$(printf '%s' "$ent" | cut -d: -f3)
		case $uid in '' | *[!0-9]*) die "user $a has no numeric UID" ;; esac
		smin=$(awk '$1 == "SYS_UID_MIN" { print $2 }' /etc/login.defs 2>/dev/null)
		smax=$(awk '$1 == "SYS_UID_MAX" { print $2 }' /etc/login.defs 2>/dev/null)
		case $smin in '' | *[!0-9]*) smin=100 ;; esac
		case $smax in '' | *[!0-9]*) smax=999 ;; esac
		[ "$smin" -ge 1 ] || smin=1
		{ [ "$uid" -ge "$smin" ] && [ "$uid" -le "$smax" ]; } || die "user $a has UID $uid, outside the system range"
		want=$({
			echo "$b"
			grep -E "^member $a " "$STAGE/packaging/accounts.conf" | cut -d' ' -f3
		} | sort | tr '\n' ',')
		have=$(id -nG "$a" | tr ' ' '\n' | sort | tr '\n' ',')
		[ "$want" = "$have" ] || die "user $a is in the groups '$have', expected '$want'"
	done <"$STAGE/packaging/accounts.conf"
	grep -E '^group ' "$STAGE/packaging/accounts.conf" | while read -r _ g; do
		gid=$(getent group "$g" | cut -d: -f3)
		want=$(grep -E "^user [^ ]+ $g " "$STAGE/packaging/accounts.conf" | cut -d' ' -f2 | sort | tr '\n' ',')
		have=$(getent passwd | awk -F: -v g="$gid" '$4 == g { print $1 }' | sort | tr '\n' ',')
		[ "$want" = "$have" ] || die "group $g is the primary group of '$have', expected '$want'"
	done
}

# hold_services: policy-rc.d is what invoke-rc.d and deb-systemd-invoke ask before a
# maintainer script starts or stops a service; 101 means "forbidden". An
# administrator's own policy-rc.d is set aside and put back by release_services.
hold_services() {
	if [ -e "$PRC" ] || [ -L "$PRC" ]; then
		if ! grep -qF "$PRC_MARK" "$PRC" 2>/dev/null && [ ! -e "$PRC.ctrlz-saved" ]; then
			mv "$PRC" "$PRC.ctrlz-saved"
		fi
	fi
	# The file expires by itself: cleanup removes it on every exit it can catch, but not
	# on SIGKILL, the OOM killer or a power cut, and a forgotten "exit 101" would keep
	# every later security update from restarting its daemon (p4n-W5c-r4-5). After an
	# hour it answers 0 (allowed), long past any apt run, and a later apply.sh removes it.
	printf '#!/bin/sh\n%s\n[ $(( $(date +%%s) - %s )) -lt 3600 ] || exit 0\nexit 101\n' "$PRC_MARK" "$(date +%s)" >"$PRC.new"
	chmod 0755 "$PRC.new"
	mv -f "$PRC.new" "$PRC"
}

# put_chrony_conf writes the node's fixed chrony.conf before the chrony package is
# installed, keeping the host's own file once as chrony.conf.ctrlz-orig. What was
# there is also copied into the staging directory, so a failed apt can put it back.
put_chrony_conf() {
	! pkg_here chrony || CHRONY_WAS_HERE=1
	while read -r src dest mode; do
		case $src in '' | '#'*) continue ;; esac
		[ "$dest" = /etc/chrony/chrony.conf ] || continue
		if [ -e "$dest" ]; then
			cp -p "$dest" "$STAGE/chrony.conf.prev"
			CHRONY_PREV="$STAGE/chrony.conf.prev"
			if [ ! -e "$dest.ctrlz-orig" ]; then
				cp -p "$dest" "$dest.ctrlz-orig"
				CHRONY_ORIG_NEW=1
			fi
		else
			CHRONY_PREV=none
		fi
		put "$STAGE/packaging/$src" "$dest" "$mode"
	done <"$STAGE/packaging/files.conf"
}

# mask_distribution_unbound masks the distribution's unit (masking works before the
# unit exists) and remembers which masks are new, for revert_pre_apt.
mask_distribution_unbound() {
	! pkg_here unbound || UNBOUND_WAS_HERE=1
	for u in unbound.service unbound-resolvconf.service; do
		[ "$(readlink "/etc/systemd/system/$u" 2>/dev/null)" = /dev/null ] || MASKED_BY_US="$MASKED_BY_US $u"
	done
	systemctl mask unbound.service unbound-resolvconf.service >/dev/null 2>&1 || true
}

# --- packages ---------------------------------------------------------------------
# Only what the bundle holds, with apt's network sources off: no index, no mirror,
# no download (T-359). apt resolves the bundle's packages against each other and
# what is installed.
apply_packages() {
	set -- "$STAGE"/debs/*.deb
	[ -e "$1" ] || die 'the bundle holds no packages'

	# A package the host already holds at a newer revision than the bundle's (a
	# security update its own apt took) is left alone: apt refuses a downgrade, and
	# forcing one would undo the update. The floor check below still applies to what
	# is installed in the end.
	n=$#
	while [ "$n" -gt 0 ]; do
		f=$1
		shift
		n=$((n - 1))
		pkg=$(dpkg-deb --field "$f" Package) && bv=$(dpkg-deb --field "$f" Version) || die 'a package of the bundle cannot be read'
		if [ "$(dpkg-query -W -f='${db:Status-Status}' "$pkg" 2>/dev/null)" = installed ]; then
			iv=$(dpkg-query -W -f='${Version}' "$pkg")
			if dpkg --compare-versions "$iv" gt "$bv"; then
				continue
			fi
		fi
		set -- "$@" "$f"
	done

	if [ $# -gt 0 ]; then
		# chrony and systemd-timesyncd both provide and conflict with time-daemon, and a
		# stock Ubuntu server has timesyncd. It goes out in the same apt transaction that
		# brings chrony in ("systemd-timesyncd-"): apt waits for the dpkg lock for the
		# removal too, and a transaction that fails leaves timesyncd installed. A purge
		# by hand first would run without the lock wait and could not be undone, since
		# with no package source apt cannot find a purged package again (r5-2, r5-3, r5-8).
		if [ "$(dpkg-query -W -f='${db:Status-Status}' systemd-timesyncd 2>/dev/null)" = installed ]; then
			set -- "$@" systemd-timesyncd-
		fi

		# Ask apt first, changing nothing (-s): do the packages resolve, and what would
		# it remove? Only systemd-timesyncd may go. Everything that can fail on the
		# bundle itself (a gap in the closure, a held package, a package that depends on
		# timesyncd) fails here, before anything on the host has changed.
		# shellcheck disable=SC2086
		sim=$(DEBIAN_FRONTEND=noninteractive apt-get -s -y --no-install-recommends \
			$APT_OPTS -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=300 install "$@" 2>/dev/null) || die 'the packages of the bundle do not resolve; nothing was changed'
		# Remv and Purg both: a host that purges still prints what it would take away.
		removed=$(printf '%s\n' "$sim" | sed -n -e 's/^Remv \([^ ]*\).*/\1/p' -e 's/^Purg \([^ ]*\).*/\1/p' | grep -vx 'systemd-timesyncd' || true)
		[ -z "$removed" ] || die 'the packages of the bundle would remove other packages; nothing was changed'
	fi

	# No service may start while the packages install, and the distribution's own
	# configs must not run: chrony's postinst would start chronyd on Ubuntu's NTS pool
	# sources (international NTP traffic) and unbound would start with the stock config
	# on 127.0.0.1:53, both before anything of the node exists. So the node's
	# chrony.conf is in place first (dpkg keeps it, --force-confold), the distribution's
	# Unbound units are masked and a policy-rc.d forbids every start until apt is done.
	# These come after the dry run, so a bundle that does not resolve changes nothing;
	# when apt itself fails, cleanup puts the chrony.conf and the masks back.
	PRE_APT=1
	put_chrony_conf
	mask_distribution_unbound
	hold_services

	if [ $# -gt 0 ]; then
		# The dpkg lock is held for minutes by unattended-upgrades and the apt timers on a
		# stock server: wait for it instead of failing the install.
		# shellcheck disable=SC2086
		DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends \
			$APT_OPTS -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=300 \
			install "$@" >/dev/null || die 'the packages of the bundle did not install'
	fi
	PRE_APT=0
	release_services

	for p in unbound dns-root-data chrony nftables polkitd; do
		[ "$(dpkg-query -W -f='${db:Status-Status}' "$p" 2>/dev/null)" = installed ] || die "package $p is not installed after the bundle"
	done
	v=$(dpkg-query -W -f='${Version}' unbound)
	dpkg --compare-versions "$v" ge "$UNBOUND_FLOOR" || die "unbound $v is under the version floor $UNBOUND_FLOOR"

	# The distribution's own Unbound is not ours: it would listen on 127.0.0.1:53
	# with the distribution's config, outside the agent's supervision. The units of
	# the node are ctrlz-unbound and ctrlz-unbound-free.
	systemctl disable --now unbound.service >/dev/null 2>&1 || true
	systemctl mask unbound.service unbound-resolvconf.service >/dev/null 2>&1 || true
}

# put SRC DEST MODE: root-owned, atomic, so a running reader never sees half a file.
put() {
	mkdir -p "$(dirname "$2")"
	install -m "$3" -o root -g root "$1" "$2.new" && mv -f "$2.new" "$2"
}

apply_binaries() {
	put "$STAGE/bin/ctrlz-node" /usr/local/bin/ctrlz-node 0755
	put "$STAGE/bin/ctrlz-verify" /usr/local/sbin/ctrlz-verify 0755
}

apply_dirs() {
	while read -r path owner group mode; do
		case $path in '' | '#'*) continue ;; esac
		# plain_dirs refused a link before anything changed; -h keeps chown from
		# following one that appeared since.
		[ ! -L "$path" ] || die "$path is a symbolic link; refusing to follow it"
		mkdir -p "$path"
		chown -h "$owner:$group" "$path"
		# Five digits: a four-digit numeric mode keeps the setgid bit a directory inherited
		# from its parent, which would turn 0700 into 2700.
		chmod "0$mode" "$path"
	done <"$STAGE/packaging/dirs.conf"
}

# apparmor_active: the kernel enforces AppArmor profiles. aa-enabled says so where it
# exists (the apparmor package, on every Ubuntu 24.04 image); the module parameter is
# the same answer without it.
apparmor_active() {
	if command -v aa-enabled >/dev/null 2>&1; then
		aa-enabled --quiet >/dev/null 2>&1
		return
	fi
	[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = Y ]
}

apply_files() {
	while read -r src dest mode; do
		case $src in '' | '#'*) continue ;; esac
		# chrony.conf went in before the package (put_chrony_conf).
		[ "$dest" != /etc/chrony/chrony.conf ] || continue
		put "$STAGE/packaging/$src" "$dest" "$mode"
	done <"$STAGE/packaging/files.conf"

	# Ubuntu confines /usr/sbin/unbound and /usr/sbin/chronyd with AppArmor profiles;
	# the local additions written above let the two node Unbound units use their own
	# directories and chronyd read the agent's drop-in. Reload the profiles so they
	# are in force before the agent starts either unit. A host with no such profile
	# has nothing to reload.
	# Only where AppArmor is in force: on a host booted without it (apparmor=0, a kernel
	# or a container VPS without the module) there is nothing to reload, the tool may
	# fail, and the install must not stop for that.
	for prof in usr.sbin.unbound usr.sbin.chronyd; do
		if apparmor_active && [ -f "/etc/apparmor.d/$prof" ] && command -v apparmor_parser >/dev/null 2>&1; then
			apparmor_parser -r "/etc/apparmor.d/$prof" || die "the AppArmor profile $prof did not reload"
		fi
	done

	# The free Unbound's CPU ceiling is a quarter of the host: systemd's CPUQuota is
	# per CPU, so it is 25% times the number of CPUs.
	n=$(nproc 2>/dev/null || echo 1)
	case $n in '' | *[!0-9]*) n=1 ;; esac
	mkdir -p /etc/systemd/system/ctrlz-unbound-free.service.d
	printf '[Service]\nCPUQuota=%s%%\n' "$((n * 25))" >/etc/systemd/system/ctrlz-unbound-free.service.d/10-limits.conf
	chmod 0644 /etc/systemd/system/ctrlz-unbound-free.service.d/10-limits.conf
}

# --- identity and configuration (first install only) ---------------------------
apply_identity() {
	K=/var/lib/ctrlz/keys
	[ -d "$K" ] && [ ! -L "$K" ] || die "$K is not a plain directory"
	# An earlier key or an unfinished enrolment is never carried over: the agent
	# makes a fresh key for every Enroll (T-078). rm removes a link itself and does
	# not follow it.
	rm -f "$K/node.key" "$K/node.crt" "$K/enroll.pending" "$K/enroll.token"
	hubcfg=$HUB
	case $HUB in
	\[*) ;;
	*:*:*) hubcfg="[$HUB]" ;;
	esac
	cat >/etc/ctrlz/agent.conf.new <<EOF
# Written by the install (p4-nodes 4.2); read by the agent and by dns.
hub=$hubcfg
dns_bind_ip=$DNS_BIND
dns_advertised_ip=$DNS_ADV
proxy_bind_ip=$PROXY_BIND
proxy_advertised_ip=$PROXY_ADV
EOF
	[ -z "$FREE_OUT" ] || printf 'free_outgoing_interface=%s\n' "$FREE_OUT" >>/etc/ctrlz/agent.conf.new
	[ -z "$PANEL_ADDRS" ] || printf 'panel_addrs=%s\n' "$PANEL_ADDRS" >>/etc/ctrlz/agent.conf.new
	chmod 0644 /etc/ctrlz/agent.conf.new
	mv -f /etc/ctrlz/agent.conf.new /etc/ctrlz/agent.conf

	# Files the agent reads: the trusted root (its hash was checked against the
	# install command), the node CA and the hub key pin (fetched under that pin).
	# The root is also kept root-owned, where the upgrade verifies against it and
	# the agent cannot write.
	# Every file goes in as a fresh one: the target is removed first, so a link the
	# agent left there is replaced and never written through.
	put_agent "$ROOT_JSON" "$K/root.json"
	put_agent "$NODE_CA" "$K/node_ca.pem"
	printf '%s\n' "$PIN" >"$STAGE/hub.pin.tmp"
	put_agent "$STAGE/hub.pin.tmp" "$K/hub.pin"
	rm -f "$STAGE/hub.pin.tmp"
	put "$ROOT_JSON" /etc/ctrlz/root.json 0644
	if [ -n "$TOKEN_FILE" ]; then
		# The enrolment token the agent sends once with Enroll, and deletes after.
		put_agent "$TOKEN_FILE" "$K/enroll.token"
	fi
}

# put_agent SRC DEST: a file of the agent's keys directory, 0600, as a new file.
put_agent() {
	rm -f "$2"
	install -m 0600 -o ctrlz-agent -g ctrlz "$1" "$2"
}

# apport (a stock Ubuntu Server has it) makes kernel.core_pattern a pipe to its own
# handler, which the agent refuses: it will not start either Unbound while a core
# could be kept (SC 5.2a). The service is stopped and masked so it cannot put its
# pattern back at boot, and 60-ctrlz.conf sets the pattern the agent accepts.
mask_apport() {
	for d in /usr/lib/systemd/system /lib/systemd/system /etc/systemd/system; do
		if [ -e "$d/apport.service" ]; then
			systemctl disable --now apport.service >/dev/null 2>&1 || true
			systemctl mask apport.service >/dev/null 2>&1 || true
			return 0
		fi
	done
}

apply_kernel() {
	mask_apport
	modprobe nf_conntrack >/dev/null 2>&1 || true
	sysctl -p /etc/sysctl.d/60-ctrlz.conf >/dev/null || die 'the sysctl settings of the node did not apply'
}

# restart_stale_unbound restarts a node Unbound whose running binary is gone from disk.
# The package upgrade replaced /usr/sbin/unbound, but the process keeps serving the old
# code; the agent only finds the unit active and reloads its config, which keeps the
# executable. The floor check passes on the installed version, so without this a fixed
# package would leave the vulnerable process answering until the next reboot (r5-7).
# It looks at the running process and not at a flag of this run, so a run that was
# killed after apt and is repeated still restarts it. A unit the agent has not started
# has no process and is left alone.
#
# A library counts as much as the binary: the bundle's closure for unbound carries
# libssl3t64 (DNSSEC crypto), libevent and others, and a fix that ships only in one of
# them leaves /usr/sbin/unbound untouched while the process keeps the deleted old
# mapping (p4n-W5c-r6-6). So a mapped file under a system directory that is gone from
# disk marks the process stale too. Other deleted mappings (/dev/zero, memfd, SysV
# shared memory, a file in /tmp) are not ours to act on.
stale_process() {
	case $(readlink "/proc/$1/exe" 2>/dev/null) in
	*' (deleted)') return 0 ;;
	esac
	grep -qE ' /(usr|lib|lib64|bin|sbin|opt)/.* \(deleted\)$' "/proc/$1/maps" 2>/dev/null
}

restart_stale_unbound() {
	for u in ctrlz-unbound.service ctrlz-unbound-free.service; do
		pid=$(systemctl show -p MainPID --value "$u" 2>/dev/null) || continue
		case $pid in '' | 0 | *[!0-9]*) continue ;; esac
		if stale_process "$pid"; then
			systemctl restart "$u" >/dev/null || die "$u could not be restarted on the new unbound"
		fi
	done
}

apply_services() {
	systemctl daemon-reload
	restart_stale_unbound
	# The Unbound units are not enabled: the agent starts them after its checks.
	systemctl enable ctrlz-agent.service ctrlz-dns.service ctrlz-proxy.service chrony.service >/dev/null 2>&1 || die 'enabling the units failed'
	# chrony.service conflicts with systemd-timesyncd, which apt removed with its package;
	# a copy of it that was still running is stopped here.
	systemctl stop systemd-timesyncd.service >/dev/null 2>&1 || true
	systemctl restart chrony.service >/dev/null 2>&1 || true
	# restart, in both modes: quiesce stopped them, and a repeat install has replaced
	# the binary and (in install mode) the identity files, which a unit that kept
	# running would not see until its next restart. dns and the agent start without
	# relying on an order: dns serves plain DNS from its last image until the agent
	# hands it a NodeConfig, and the agent restarts dns when that NodeConfig changes
	# what dns bound (7.3).
	systemctl restart ctrlz-agent.service ctrlz-dns.service ctrlz-proxy.service || die 'starting the units failed'
}

apply_version() {
	# Written last, so a failed run leaves the old version and can be run again. The
	# upgrade reads it to refuse anything not above it, and ctrlz-verify to refuse a
	# rollback (SC 13).
	printf '%s\n' "$VERSION" >/etc/ctrlz/versions/node.new
	chmod 0644 /etc/ctrlz/versions/node.new
	mv -f /etc/ctrlz/versions/node.new /etc/ctrlz/versions/node
}

# The order matters: accounts and packages first, with the services still running (a
# failure there leaves the node as it was); then the services stop and the agent's tree
# is touched; accounts before the directories that name them, packages
# before the files that overwrite their conffiles, everything before the services.
apply_accounts
apply_packages
quiesce
plain_dirs
apply_binaries
apply_dirs
apply_files
[ "$MODE" != install ] || apply_identity
apply_kernel
apply_services
apply_version

printf 'ctrlz-install: node bundle %s %s\n' "$VERSION" "$MODE"
if [ "$MODE" = install ]; then
	printf 'The agent prints its key fingerprint and its four addresses to the journal:\n  journalctl -u ctrlz-agent\nCompare them in the admin page before you confirm the node.\n'
fi
