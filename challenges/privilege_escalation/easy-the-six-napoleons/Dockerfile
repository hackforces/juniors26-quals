FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server sudo findutils && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/bash player && echo 'player:player' | chpasswd && mkdir -p /run/sshd /srv/exhibits \
 && printf 'inventory synchronised\n' >/srv/exhibits/manifest \
 && printf 'player ALL=(root) NOPASSWD: /usr/bin/find\n' >/etc/sudoers.d/case && chmod 0440 /etc/sudoers.d/case
COPY src/entrypoint.sh src/healthcheck.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh
EXPOSE 22
HEALTHCHECK --interval=15s --timeout=4s --retries=3 CMD /usr/local/bin/healthcheck.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Минимальные привилегии для jury (root: задача решается легитимной эскалацией внутри контейнера)
LABEL org.innoctf.runtime=root
