#!/bin/sh
set -eu
[ -n "${CTF_FLAG:-}" ] || { echo "CTF_FLAG must be set" >&2; exit 1; }
umask 077
printf '%s\n' "$CTF_FLAG" >/root/flag
chmod 0400 /root/flag
printf '%s' "$CTF_FLAG" | sha256sum | cut -c1-24 >/etc/copper/token
chmod 0444 /etc/copper/token
exec /usr/sbin/sshd -D -e
