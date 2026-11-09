FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server python3 openssl iproute2 coreutils \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /usr/local/bin/case-shell player \
 && echo 'player:player' | chpasswd \
 && mkdir -p /run/sshd /etc/treaty /etc/systemd/system /var/backups /var/log/treaty /opt/treaty
RUN openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=treaty-ca -keyout /opt/treaty/ca.key -out /opt/treaty/ca.crt -days 3650 \
 && openssl req -newkey rsa:2048 -nodes -subj /CN=treaty-archive -keyout /opt/treaty/server.key -out /opt/treaty/server.csr \
 && openssl x509 -req -in /opt/treaty/server.csr -CA /opt/treaty/ca.crt -CAkey /opt/treaty/ca.key -CAcreateserial -out /opt/treaty/server.crt -days 3650 \
 && openssl req -newkey rsa:2048 -nodes -subj /CN=night-clerk -keyout /opt/treaty/client.key -out /opt/treaty/client.csr \
 && openssl x509 -req -in /opt/treaty/client.csr -CA /opt/treaty/ca.crt -CAkey /opt/treaty/ca.key -CAcreateserial -out /opt/treaty/client.crt -days 3650 \
 && chmod 600 /opt/treaty/*.key
COPY src/archive.py src/client.py /usr/local/lib/
COPY src/case-shell src/derive-pass.sh src/entrypoint.sh src/healthcheck.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/case-shell /usr/local/bin/derive-pass.sh /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh
EXPOSE 22
HEALTHCHECK --interval=15s --timeout=4s --retries=3 CMD /usr/local/bin/healthcheck.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Минимальные привилегии для jury (root: задача решается легитимной эскалацией внутри контейнера)
LABEL org.innoctf.runtime=root
