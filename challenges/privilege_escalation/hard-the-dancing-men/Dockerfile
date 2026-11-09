FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server sudo && rm -rf /var/lib/apt/lists/* \
 && groupadd players && useradd -m -s /bin/bash -G players player && echo 'player:player' | chpasswd \
 && mkdir -p /run/sshd /srv/ledger /var/lib/ledger && touch /var/lib/ledger/archive.log
COPY src/reconcile.sh /usr/local/sbin/reconcile
COPY src/archive.sh /usr/local/bin/archive-ledger
COPY src/runtime.conf /srv/ledger/runtime.conf
COPY src/entrypoint.sh src/healthcheck.sh /usr/local/bin/
RUN chown root:root /usr/local/sbin/reconcile /usr/local/bin/archive-ledger \
 && chmod 0755 /usr/local/sbin/reconcile /usr/local/bin/archive-ledger /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh \
 && chown root:players /srv/ledger/runtime.conf && chmod 0664 /srv/ledger/runtime.conf \
 && printf 'player ALL=(root) NOPASSWD: /usr/local/sbin/reconcile\n' >/etc/sudoers.d/case && chmod 0440 /etc/sudoers.d/case
EXPOSE 22
HEALTHCHECK --interval=15s --timeout=4s --retries=3 CMD /usr/local/bin/healthcheck.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Минимальные привилегии для jury (root: задача решается легитимной эскалацией внутри контейнера)
LABEL org.innoctf.runtime=root
