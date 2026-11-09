# syntax=docker/dockerfile:1
# The Red Circle — five chained restricted shells in one container.
# Escaping level N yields the password for level N+1; level 5 yields the
# runtime flag. Chain keys are derived from the flag at container start.

FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/nextkey.c .
RUN gcc -O2 -Wall -Wextra nextkey.c -o nextkey

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server openssh-client mawk vim less procps bash \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/nextkey /usr/local/bin/nextkey
COPY src/kartoteka.sh /usr/local/bin/kartoteka
COPY src/sshd_config /etc/ssh/sshd_config
COPY src/motd /etc/motd
COPY src/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY src/healthcheck.sh /usr/local/bin/healthcheck.sh
COPY src/homes/ /etc/pip-homes/
RUN <<'EOS'
set -eux
rm -f /etc/update-motd.d/*
sed -i '/pam_motd/d' /etc/pam.d/sshd
truncate -s0 /etc/legal
# pam_limits is not in debian's default sshd PAM stack; nproc caps need it
printf 'session required pam_limits.so\n' >> /etc/pam.d/sshd
for n in 1 2 3 4 5; do
  printf 'level%s hard nproc 128\nlevel%s soft nproc 128\n' "$n" "$n"
done > /etc/security/limits.d/pips.conf
# vim swap files must not try the read-only home
printf 'set directory=/tmp\n' >> /etc/vim/vimrc
echo '/usr/local/bin/kartoteka' >> /etc/shells
chmod 755 /usr/local/bin/kartoteka /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh
chown root:root /usr/local/bin/nextkey
chmod 4755 /usr/local/bin/nextkey
# five users: rbash levels 1-4, the kartoteka menu for level 5
useradd -m -u 1001 -d /home/level1 -s /bin/rbash level1
useradd -m -u 1002 -d /home/level2 -s /bin/rbash level2
useradd -m -u 1003 -d /home/level3 -s /bin/rbash level3
useradd -m -u 1004 -d /home/level4 -s /bin/rbash level4
useradd -m -u 1005 -d /home/level5 -s /usr/local/bin/kartoteka level5
# public entry credentials only; levels 2-5 get flag-derived keys at start
echo 'level1:level1' | chpasswd
# rbash fallback if the bash package did not ship the symlink
[ -e /bin/rbash ] || ln -s /bin/bash /bin/rbash
# lay out clean homes from the skeletons (which carry the per-level bin/
# symlinks: the entrypoint wipes and restores whole homes at every start),
# drop distro skel leftovers
for n in 1 2 3 4 5; do
  rm -f "/home/level$n/.bashrc" "/home/level$n/.bash_logout" "/home/level$n/.profile"
  cp -a "/etc/pip-homes/level$n/." "/home/level$n/"
done
# homes deliberately root-owned read-only: no ~/.profile or ~/bin tampering
chown -R root:root /home/level1 /home/level2 /home/level3 /home/level4 /home/level5
chmod 755 /home/level1 /home/level2 /home/level3 /home/level4 /home/level5 \
          /home/level1/bin /home/level2/bin /home/level3/bin /home/level4/bin
mkdir -p /run/sshd
EOS
EXPOSE 22
HEALTHCHECK --interval=15s --timeout=4s --retries=3 CMD /usr/local/bin/healthcheck.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Минимальные привилегии для jury (root: задача решается легитимной эскалацией внутри контейнера)
LABEL org.innoctf.runtime=root
