#!/bin/sh
set -eu
: "${CTF_FLAG:?Set CTF_FLAG before starting}"
install -d -m 0750 -o fastcalc -g fastcalc /run/case
printf '%s\n' "$CTF_FLAG" > /run/case/flag
chown fastcalc:fastcalc /run/case/flag; chmod 0400 /run/case/flag
exec setpriv --reuid=fastcalc --regid=fastcalc --init-groups /usr/local/bin/fastcalc-vm
