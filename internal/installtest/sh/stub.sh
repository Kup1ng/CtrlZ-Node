#!/bin/sh
# Stand-in for systemctl, sysctl, modprobe and journalctl in the install test: it
# records its call and fails the test when the enrolment token is in its
# arguments or in its environment (the token must reach no child, p4-nodes 4.2,
# N7). The real commands are not run: the container has no systemd.
name=${0##*/}
mkdir -p /var/log/stub
printf '%s %s\n' "$name" "$*" >>/var/log/stub/calls.log
if [ -r /stubcfg/token ]; then
	T=$(cat /stubcfg/token)
	case "$*" in *"$T"*)
		echo "TOKEN IN ARGV of $name" >>/var/log/stub/LEAK
		exit 99
		;;
	esac
	if env | grep -qF -f /stubcfg/token; then
		echo "TOKEN IN ENVIRONMENT of $name" >>/var/log/stub/LEAK
		exit 99
	fi
fi
if [ "$name" = sysctl ] && [ -e /stubcfg/fail-sysctl ]; then
	exit 1
fi
# systemctl show -p MainPID --value UNIT: the pid a scenario put in /stubcfg/mainpid.UNIT.
if [ "$name" = systemctl ] && [ "${1:-}" = show ]; then
	for last in "$@"; do :; done
	[ ! -r "/stubcfg/mainpid.$last" ] || cat "/stubcfg/mainpid.$last"
	exit 0
fi
# A stateful systemd for the scenarios that need a unit to really stop: units
# listed in /stubcfg/running are active, stop removes one and start or restart adds
# one. Only when the file exists, so the other scenarios see the plain stub.
if [ "$name" = systemctl ] && [ -e /stubcfg/running ]; then
	verb=${1:-}
	case $verb in
	stop | start | restart)
		shift
		for u in "$@"; do
			case $u in -*) continue ;; esac
			grep -vxF "$u" /stubcfg/running >/stubcfg/running.new
			[ "$verb" = stop ] || echo "$u" >>/stubcfg/running.new
			mv /stubcfg/running.new /stubcfg/running
		done
		exit 0
		;;
	is-active)
		for last in "$@"; do :; done
		if grep -qxF "$last" /stubcfg/running; then
			echo active
			exit 0
		fi
		echo inactive
		exit 3
		;;
	esac
fi
if [ "$name" = systemctl ] && [ "${1:-}" = is-active ]; then
	# A unit listed in /stubcfg/active stays active whatever was asked: a stop that
	# did not take effect.
	for last in "$@"; do :; done
	if [ -r /stubcfg/active ] && grep -qxF "$last" /stubcfg/active; then
		echo active
		exit 0
	fi
	echo inactive
	exit 3
fi
exit 0
