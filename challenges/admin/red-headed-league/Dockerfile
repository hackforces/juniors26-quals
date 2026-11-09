FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server python3 iproute2 netcat-openbsd coreutils \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /usr/local/bin/case-shell player \
 && echo 'player:player' | chpasswd \
 && mkdir -p /run/sshd /etc/red
COPY src/desk.py /usr/local/lib/red-desk.py
COPY src/case-shell src/entrypoint.sh src/healthcheck.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/case-shell /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh
EXPOSE 22
HEALTHCHECK --interval=15s --timeout=4s --retries=3 CMD /usr/local/bin/healthcheck.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Минимальные привилегии для jury (root: задача решается легитимной эскалацией внутри контейнера)
LABEL org.innoctf.runtime=root
