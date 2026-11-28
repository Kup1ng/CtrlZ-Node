#!/bin/sh
# Stand-in for curl in the install test. It serves files from /hub as the panel's
# /install/... routes would, and it enforces what node.sh promises about how it
# calls curl: the hub's key pin and -k on every call, the token only on bundle
# files and only as `-H @file`, never in an argument or the environment.
mkdir -p /var/log/stub
echo "curl $*" >>/var/log/stub/curl.args
if [ -r /stubcfg/token ]; then
	T=$(cat /stubcfg/token)
	case "$*" in *"$T"*)
		echo "TOKEN IN ARGV of curl" >>/var/log/stub/LEAK
		exit 99
		;;
	esac
	if env | grep -qF -f /stubcfg/token; then
		echo "TOKEN IN ENVIRONMENT of curl" >>/var/log/stub/LEAK
		exit 99
	fi
fi

out=
hdr=
pin=
insecure=
maxf=
retry=
retrydelay=
url=
while [ $# -gt 0 ]; do
	case $1 in
	--output)
		out=$2
		shift
		;;
	-H)
		hdr=$2
		shift
		;;
	--pinnedpubkey)
		pin=$2
		shift
		;;
	--insecure) insecure=1 ;;
	--max-filesize)
		maxf=$2
		shift
		;;
	--retry)
		retry=$2
		shift
		;;
	--retry-delay)
		retrydelay=$2
		shift
		;;
	--proto | --connect-timeout | --max-time) shift ;;
	--tlsv1.3 | --fail | --silent | --show-error) ;;
	https://*) url=$1 ;;
	*)
		echo "curl stub: unexpected argument" >&2
		exit 2
		;;
	esac
	shift
done

[ -n "$out" ] && [ -n "$url" ] || exit 2
if [ "$pin" != "$(cat /stubcfg/pin)" ] || [ -z "$insecure" ]; then
	echo "BAD PIN OR NO -k: $url" >>/var/log/stub/LEAK
	exit 60
fi
# The hub rate-limits /install (5.1): every call must ask curl to retry, with the delay
# that spans a rate-limit window (curl retries 429 and 503; the stub cannot play the
# hub's limiter, so it checks that every call asks for the retry).
if [ "$retry" != 5 ] || [ "$retrydelay" != 15 ]; then
	echo "NO RETRY: $url" >>/var/log/stub/LEAK
	exit 22
fi
rest=${url#https://}
path=/${rest#*/}
echo "$path" >>/var/log/stub/fetch.log

case $path in
/install/bundle/*)
	case $hdr in @*) ;; *)
		echo "bundle file without -H @file: $path" >>/var/log/stub/LEAK
		exit 22
		;;
	esac
	# The header file holds exactly "Authorization: Bearer <token>".
	cmp -s "${hdr#@}" /stubcfg/token.hdr || exit 22
	;;
*)
	if [ -n "$hdr" ]; then
		echo "token sent with a non-bundle request: $path" >>/var/log/stub/LEAK
		exit 22
	fi
	;;
esac
[ -f "/hub$path" ] || exit 22
# curl's own rule: a body over --max-filesize is refused (exit 63) and nothing is kept.
if [ -n "$maxf" ] && [ "$(wc -c <"/hub$path")" -gt "$maxf" ]; then
	echo "$path" >>/var/log/stub/refused-size.log
	exit 63
fi
cp "/hub$path" "$out"
