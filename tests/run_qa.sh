#!/bin/sh

set -e

test_family() {
	f=$1
	xt=$2

	for file in options-"$f".* ;do
		echo "restoring $file"
		"$xt"tables-restore < "$file"
	done
}

test_family ipv4 ip
test_family ipv6 ip6

TMPA=$(mktemp) || exit 111
TMPB=$(mktemp) || exit 111

iptables-save > "$TMPA"
(iptables-save | iptables-restore) || exit 111
iptables-save > "$TMPB"

echo "iptables diff"
diff -u "$TMPA" "$TMPB"

rm "$TMPA" "$TMPB"

ip6tables-save > "$TMPA"
(ip6tables-save | ip6tables-restore) || exit 111
ip6tables-save > "$TMPB"

echo "ip6tables diff"
diff -u "$TMPA" "$TMPB"

rm "$TMPA" "$TMPB"


