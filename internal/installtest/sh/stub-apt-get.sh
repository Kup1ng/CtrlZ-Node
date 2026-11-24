#!/bin/sh
# Wrapper around the real apt-get in the install test. It records the call, can fail
# it on request (a held dpkg lock past its timeout, a bundle that does not resolve),
# and otherwise runs /usr/bin/apt-get itself, so the options of apply.sh meet real apt:
# an earlier stand-in that installed with `dpkg -i` accepted --no-download and a
# purged package that real apt rejects (p4n-W5c-r5-1, r5-5, r5-8). The container has
# no network and apply.sh turns the package sources off, as on a node.
mkdir -p /var/log/stub
echo "apt-get $*" >>/var/log/stub/apt.log
# A scenario that has installed the packages once and only repeats refusals may skip the apt work.
[ -e /stubcfg/apt-noop ] && exit 0
sim=0
for a in "$@"; do
	[ "$a" != -s ] || sim=1
done
if [ "$sim" = 1 ]; then
	# The dry run apply.sh makes before it touches anything. It changes nothing in apt.
	[ ! -e /stubcfg/fail-apt-sim ] || exit 100
	exec /usr/bin/apt-get "$@"
fi
# What the host looks like at the moment apt runs: no maintainer script may start a
# service (policy-rc.d forbids it), the distribution's Unbound is masked and the
# node's chrony.conf is already in place.
{
	if [ -x /usr/sbin/policy-rc.d ]; then
		/usr/sbin/policy-rc.d chrony start
		echo "policy-rc.d exit $?"
		cp /usr/sbin/policy-rc.d /var/log/stub/policy-rc.d.copy
	else
		echo "policy-rc.d absent"
	fi
	grep -q '^confdir /etc/ctrlz/chrony' /etc/chrony/chrony.conf 2>/dev/null && echo "chrony.conf ours" || echo "chrony.conf not ours"
	grep -q '^systemctl mask unbound.service' /var/log/stub/calls.log 2>/dev/null && echo "unbound masked" || echo "unbound not masked"
} >>/var/log/stub/apt.state
# The first real run fails and later ones work: a lock timeout that clears.
if [ -e /stubcfg/fail-apt-once ]; then
	rm -f /stubcfg/fail-apt-once
	exit 100
fi
[ ! -e /stubcfg/fail-apt ] || exit 100
# dpkg did all of its work and the run still ends in an error (a later postinst failed,
# the disk filled up): the packages are configured, the exit code is not 0.
if [ -e /stubcfg/fail-apt-after ]; then
	rm -f /stubcfg/fail-apt-after
	/usr/bin/apt-get "$@"
	exit 100
fi
exec /usr/bin/apt-get "$@"
