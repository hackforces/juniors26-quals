#!/bin/sh
# retro-heap entrypoint: /flag.txt пишется из env CTF_FLAG на старте (не в build),
# владелец root, чтение только pwn; оба сервиса дропаются до пользователя pwn.
set -e

[ -n "${CTF_FLAG:-}" ] || { echo "entrypoint: CTF_FLAG must be set" >&2; exit 1; }

printf '%s\n' "$CTF_FLAG" > /flag.txt
chown root:pwn /flag.txt
chmod 440 /flag.txt

setpriv --reuid=pwn --regid=pwn --clear-groups \
    python3 /srv/server.py &

exec setpriv --reuid=pwn --regid=pwn --clear-groups \
    socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/run_chal.sh
