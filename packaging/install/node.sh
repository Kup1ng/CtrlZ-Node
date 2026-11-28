#!/bin/sh
# node.sh installs a Ctrl Z node (p4-nodes 4.2 steps 1 and 2). The admin pastes the
# command the panel shows:
#
#   printf %s '<token>' | sudo sh /tmp/ctrlz-node.sh --hub HOST --pin sha256//SPKI \
#       --token-stdin --root SHA256 --dns-bind-ip A --dns-advertised-ip B \
#       --proxy-bind-ip C --proxy-advertised-ip D
#
# The command checked this script's own SHA-256 first. From here the order is the
# design: refuse anything but Ubuntu 24.04 before any change; under the hub's key
# pin fetch root.json and check it against --root before anything else; then the
# node CA, ctrlz-verify (checked against the SHA-256 the release job wrote into
# this file) and the bundle; ctrlz-verify checks the signatures against that root
# and every file against the manifest; only then does anything install, by
# apply.sh from the bundle. The binary being installed never verifies itself.
#
# The token goes in on stdin, into a file of mode 0600 on /run (memory), and to
# curl only as -H @file. It is in no argument, no environment of a child and no
# log; this script prints nothing it read.
set -eu
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# Stamped by the release job (ctrlz-bundle build).
VERIFY_SHA256='@CTRLZ_VERIFY_SHA256@'
BUNDLE_VERSION='@CTRLZ_BUNDLE_VERSION@'

die() {
	printf 'ctrlz-install: %s\n' "$*" >&2
	exit 1
}

WORK=
TOK=
cleanup() {
	[ -z "$TOK" ] || rm -rf "$TOK"
	[ -z "$WORK" ] || rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# --- 1. what this host is, before anything else -------------------------------------
# Plan "نصب نود": Ubuntu 24.04 only, every other release is refused here, before a
# token is read, a file is made or a byte is fetched.
os_field() {
	grep -m1 "^$1=" /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d "\"'"
}
[ "$(os_field ID)" = ubuntu ] && [ "$(os_field VERSION_ID)" = 24.04 ] || die 'this host is not Ubuntu 24.04; nothing was changed'
[ "$(dpkg --print-architecture 2>/dev/null)" = amd64 ] || die 'this host is not amd64; nothing was changed'
[ "$(id -u)" = 0 ] || die 'must run as root'
case $VERIFY_SHA256 in *[!0-9a-f]* | '') die 'this script was not stamped by the release job' ;; esac
[ "${#VERIFY_SHA256}" = 64 ] || die 'this script was not stamped by the release job'
case $BUNDLE_VERSION in '' | *[!0-9]*) die 'this script was not stamped by the release job' ;; esac

# --- 2. arguments -----------------------------------------------------------------
HUB=
PIN=
ROOT_SHA=
TOKEN_STDIN=
DNS_BIND=
DNS_ADV=
PROXY_BIND=
PROXY_ADV=
FREE_OUT=
PANEL_ADDRS=
while [ $# -gt 0 ]; do
	case $1 in
	--token-stdin)
		TOKEN_STDIN=1
		shift
		continue
		;;
	esac
	[ $# -ge 2 ] || die "option $1 needs a value"
	case $1 in
	--hub) HUB=$2 ;;
	--pin) PIN=$2 ;;
	--root) ROOT_SHA=$2 ;;
	--dns-bind-ip) DNS_BIND=$2 ;;
	--dns-advertised-ip) DNS_ADV=$2 ;;
	--proxy-bind-ip) PROXY_BIND=$2 ;;
	--proxy-advertised-ip) PROXY_ADV=$2 ;;
	--free-outgoing-ip) FREE_OUT=$2 ;;
	--panel-addrs) PANEL_ADDRS=$2 ;;
	*) die 'unknown option (the token is read from stdin only)' ;;
	esac
	shift 2
done
[ -n "$TOKEN_STDIN" ] || die '--token-stdin is required'
[ -n "$HUB" ] && [ -n "$PIN" ] && [ -n "$ROOT_SHA" ] || die '--hub, --pin and --root are required'
# In a bracket expression the "]" comes first and the "[" and "-" are literal.
case $HUB in *[!]0-9A-Za-z.:[-]*) die 'bad --hub' ;; esac
case $PIN in sha256//*) ;; *) die 'bad --pin' ;; esac
case ${PIN#sha256//} in '' | *[!A-Za-z0-9+/=]*) die 'bad --pin' ;; esac
case $ROOT_SHA in *[!0-9a-f]* | '') die 'bad --root' ;; esac
[ "${#ROOT_SHA}" = 64 ] || die 'bad --root'

# The four addresses end up in /etc/ctrlz/agent.conf, which the agent parses line by
# line. A value is an address by its characters or it is refused, here, before a token
# is read or a byte fetched; apply.sh checks again.
is_ip() {
	case $1 in '' | *[!0-9a-fA-F:.]*) return 1 ;; esac
	case $1 in *.* | *:*) return 0 ;; esac
	return 1
}
[ -n "$DNS_ADV" ] || DNS_ADV=$DNS_BIND
[ -n "$PROXY_ADV" ] || PROXY_ADV=$PROXY_BIND
for a in "$DNS_BIND" "$DNS_ADV" "$PROXY_BIND" "$PROXY_ADV"; do
	is_ip "$a" || die 'the four addresses (--dns-bind-ip, --dns-advertised-ip, --proxy-bind-ip, --proxy-advertised-ip) must be IP addresses'
done
[ -z "$FREE_OUT" ] || is_ip "$FREE_OUT" || die 'bad --free-outgoing-ip'
case $PANEL_ADDRS in *[!0-9a-fA-F:.,]*) die 'bad --panel-addrs' ;; esac

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

# The address curl dials: host, host:port, [v6] or [v6]:port, and a bare IPv6 is bracketed.
case $HUB in
\[*\]:*) HUB_ADDR=$HUB ;;
\[*\]) HUB_ADDR=$HUB:9443 ;;
*:*:*)
	HUB="[$HUB]"
	HUB_ADDR=$HUB:9443
	;;
*:*) HUB_ADDR=$HUB ;;
*) HUB_ADDR=$HUB:9443 ;;
esac

# --- 3. the token: stdin, memory, a file ---------------------------------------------
TOK=$(mktemp -d /run/ctrlz-install.XXXXXX) || die 'cannot make a directory on /run'
WORK=$(mktemp -d /var/tmp/ctrlz-install.XXXXXX) || die 'cannot make a directory on /var/tmp'
TOKEN=
IFS= read -r TOKEN || true
case $TOKEN in '' | *[!A-Za-z0-9_-]*) die 'the token on stdin is empty or not a token' ;; esac
[ "${#TOKEN}" -le 256 ] || die 'the token on stdin is too long'
printf '%s' "$TOKEN" >"$TOK/token"
printf 'Authorization: Bearer %s\n' "$TOKEN" >"$TOK/token.hdr"
TOKEN=
unset TOKEN

# fetch PATH OUT MAXBYTES [auth]: under the hub's key pin, never anywhere else. -k
# skips only the chain, which no public root signs; the pin is the authentication.
# The token, when sent, is a header read from a file. --retry makes curl try again on a
# timeout and on 408, 429, 500, 502, 503 and 504: the hub limits /install to 60 requests a
# minute per /24 and a bundle is dozens of requests, so a 429 in the middle of a good
# install is expected, not a failure (5.1; p4n-W5c-r4-1). 5 tries 15 s apart cover one window.
fetch() {
	if [ "${4:-}" = auth ]; then
		curl --fail --silent --show-error --insecure --pinnedpubkey "$PIN" --proto '=https' --tlsv1.3 \
			--connect-timeout 15 --max-time 600 --retry 5 --retry-delay 15 --max-filesize "$3" -H "@$TOK/token.hdr" \
			--output "$2" "https://$HUB_ADDR$1" || die "fetching $1 failed"
	else
		curl --fail --silent --show-error --insecure --pinnedpubkey "$PIN" --proto '=https' --tlsv1.3 \
			--connect-timeout 15 --max-time 600 --retry 5 --retry-delay 15 --max-filesize "$3" \
			--output "$2" "https://$HUB_ADDR$1" || die "fetching $1 failed"
	fi
}

# --- 4. the root, before anything else ------------------------------------------------
fetch /install/root.json "$WORK/root.json" 1048576
printf '%s  %s\n' "$ROOT_SHA" "$WORK/root.json" | sha256sum -c --status - || die 'root.json does not match --root; nothing was installed'

# --- 5. the node CA and the verifier -----------------------------------------------------
fetch /install/node_ca.pem "$WORK/node_ca.pem" 65536
head -c 27 "$WORK/node_ca.pem" | grep -q -- '-----BEGIN CERTIFICATE-----' || die 'node_ca.pem is not a certificate'

fetch /install/ctrlz-verify "$WORK/ctrlz-verify" 134217728
printf '%s  %s\n' "$VERIFY_SHA256" "$WORK/ctrlz-verify" | sha256sum -c --status - || die 'ctrlz-verify does not match the hash in this script; nothing was installed'
chmod 0700 "$WORK/ctrlz-verify"
# The hash is right, so this program may judge the addresses: before the token goes to
# the hub and before anything is installed.
check_addrs "$WORK/ctrlz-verify"

# --- 6. the bundle, verified before it is read any further ---------------------------
STAGE=$WORK/stage
mkdir -p "$STAGE"
fetch "/install/bundle/$BUNDLE_VERSION/manifest.json" "$STAGE/manifest.json" 4194304 auth

# The highest version installed before, if any: an older bundle is a rollback.
INSTALLED=0
if [ -r /etc/ctrlz/versions/node ]; then
	IFS= read -r INSTALLED </etc/ctrlz/versions/node || true
	case $INSTALLED in '' | *[!0-9]*) die '/etc/ctrlz/versions/node is not a version' ;; esac
fi

VERIFY_ARGS="--root $WORK/root.json --manifest $STAGE/manifest.json --installed $INSTALLED --version $BUNDLE_VERSION"
# shellcheck disable=SC2086
"$WORK/ctrlz-verify" sizes $VERIFY_ARGS >"$WORK/files.txt" || die 'the bundle manifest did not verify; nothing was installed'

# Each line is "SIZE PATH" from the verified manifest. The signed size is the bound of
# the download, so a hub under the pin cannot make this script write more than the
# listed bytes of a file (ctrlz-verify refuses a manifest whose sizes add up to over
# 2 GiB, so the whole bundle is bounded too); ctrlz-verify check compares hashes.
while IFS=' ' read -r sz p; do
	# ctrlz-verify already ran manifest.CheckPath on these; the script does not
	# take its word for a name that becomes a path or a size that becomes a limit.
	case $sz in '' | *[!0-9]*) die 'the manifest lists a bad size' ;; esac
	[ "${#sz}" -le 10 ] || die 'the manifest lists a bad size'
	# curl reads 0 as no limit; an empty file gets the smallest real one.
	[ "$sz" != 0 ] || sz=1
	case $p in '' | /* | *..* | *\\* | *:*) die 'the manifest names an unsafe path' ;; esac
	mkdir -p "$STAGE/$(dirname "$p")"
	fetch "/install/bundle/$BUNDLE_VERSION/$p" "$STAGE/$p" "$sz" auth </dev/null
done <"$WORK/files.txt"

# shellcheck disable=SC2086
"$WORK/ctrlz-verify" check $VERIFY_ARGS --dir "$STAGE" || die 'the bundle did not verify; nothing was installed'
# The verifier the bundle will install is the verifier that was checked here.
printf '%s  %s\n' "$VERIFY_SHA256" "$STAGE/bin/ctrlz-verify" | sha256sum -c --status - || die 'the ctrlz-verify in the bundle is not the one checked; nothing was installed'

# --- 7. install, only now -------------------------------------------------------------
set -- --stage "$STAGE" --version "$BUNDLE_VERSION" --hub "$HUB" --pin "$PIN" \
	--root-json "$WORK/root.json" --node-ca "$WORK/node_ca.pem" --enroll-token-file "$TOK/token" \
	--dns-bind-ip "$DNS_BIND" --dns-advertised-ip "${DNS_ADV:-$DNS_BIND}" \
	--proxy-bind-ip "$PROXY_BIND" --proxy-advertised-ip "${PROXY_ADV:-$PROXY_BIND}"
[ -z "$FREE_OUT" ] || set -- "$@" --free-outgoing-ip "$FREE_OUT"
[ -z "$PANEL_ADDRS" ] || set -- "$@" --panel-addrs "$PANEL_ADDRS"
sh "$STAGE/packaging/install/apply.sh" install "$@"
