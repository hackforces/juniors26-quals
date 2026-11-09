#!/bin/sh
set -eu
: "${CTF_FLAG:?personal challenge flag is required}"
printf '%s\n' "$CTF_FLAG" >/root/flag
chown root:root /root/flag; chmod 0600 /root/flag
exec /usr/sbin/sshd -D -e
