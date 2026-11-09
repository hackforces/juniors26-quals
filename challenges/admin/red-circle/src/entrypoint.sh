#!/bin/sh
# Personal target start: validate the flag env, derive the chain keys, lay
# out clean homes, regenerate host keys, then hand over to sshd.
set -eu

flag=${CTF_FLAG:-}
[ -n "$flag" ] || {
  echo "CTF_FLAG must be set — refusing to start" >&2
  exit 1
}

umask 077
mkdir -p /run/case /run/sshd

# Chain keys derive from the flag: nothing secret in git, and a restart of
# the same instance keeps every level's password valid for the team.
n=2
while [ "$n" -le 5 ]; do
  key=$(printf '%s:redcircle:%s' "$flag" "$n" | sha256sum | cut -d' ' -f1 | cut -c1-16)
  printf 'level%s:%s' "$n" "$key" | chpasswd
  printf '%s\n' "$key" > "/run/case/level$n.key"
  n=$((n + 1))
done
printf '%s\n' "$flag" > /run/case/flag

# Fresh per-instance host keys + global known_hosts for `ssh localhost` (level 4).
rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub
ssh-keygen -A >/dev/null
: > /etc/ssh/ssh_known_hosts
for pub in /etc/ssh/ssh_host_*_key.pub; do
  printf 'localhost,127.0.0.1,::1 %s\n' "$(cat "$pub")" >> /etc/ssh/ssh_known_hosts
done

# Homes are root-owned read-only; restore the clean skeleton on every start.
for n in 1 2 3 4 5; do
  find "/home/level$n" -mindepth 1 -delete
  cp -a "/etc/pip-homes/level$n/." "/home/level$n/"
done

chmod 1777 /tmp /var/tmp
exec /usr/sbin/sshd -D -e
