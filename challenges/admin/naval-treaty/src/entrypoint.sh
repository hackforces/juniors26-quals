#!/bin/sh
set -eu
[ -n "${CTF_FLAG:-}" ] || { echo "CTF_FLAG must be set" >&2; exit 1; }
printf '6f1cb8a9d4042050bakerstreet000000\n' >/etc/machine-id
printf 'case-07\n' >/etc/treaty/slot
chmod 0444 /etc/treaty/slot
pass=$(/usr/local/bin/derive-pass.sh)
openssl pkcs12 -export -inkey /opt/treaty/client.key -in /opt/treaty/client.crt -certfile /opt/treaty/ca.crt -out /var/backups/treaty-client.p12 -passout "pass:$pass" >/dev/null 2>&1
chmod 0444 /var/backups/treaty-client.p12
cat >/etc/systemd/system/treaty-archive.service <<'EOF'
[Service]
ExecStart=/usr/local/lib/archive.py
EnvironmentFile=/etc/treaty/archive.env
Documentation=archive uses a loopback-only TLS listener and a client seal
EOF
cat >/var/log/treaty/journal.log <<'EOF'
2050-06-17 03:57 rotation: client seal copied to /var/backups/treaty-client.p12
2050-06-17 03:58 rotation: seal passphrase derives via /usr/local/bin/derive-pass.sh, slot recorded in /etc/treaty/slot
2050-06-17 04:00 archive: sealed bulletin epoch=2050.06.17-04
2050-06-17 04:02 archive: listener bound to 127.0.0.1:9443
EOF
python3 /usr/local/lib/archive.py &
exec /usr/sbin/sshd -D -e
