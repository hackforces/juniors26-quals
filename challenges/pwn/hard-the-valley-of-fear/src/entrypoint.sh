#!/bin/sh
set -eu
: "${CTF_FLAG:?Set CTF_FLAG before starting}"
install -d -m 0750 -o ctf -g ctf /run/case
printf '%s\n' "$CTF_FLAG" >/run/case/flag; chown ctf:ctf /run/case/flag; chmod 0400 /run/case/flag
busybox httpd -f -p 31338 -h /www &
exec socat TCP-LISTEN:31337,reuseaddr,fork EXEC:'setpriv --reuid=ctf --regid=ctf --init-groups /opt/challenge/valley',stderr
