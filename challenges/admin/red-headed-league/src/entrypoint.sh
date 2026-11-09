#!/bin/sh
set -eu
[ -n "${CTF_FLAG:-}" ] || { echo "CTF_FLAG must be set" >&2; exit 1; }
umask 077
printf '%s' "$CTF_FLAG" | sha256sum | cut -c1-16 >/etc/red/card
chmod 0444 /etc/red/card
python3 /usr/local/lib/red-desk.py &
exec /usr/sbin/sshd -D -e
