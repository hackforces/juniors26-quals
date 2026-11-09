FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/courier.c .
RUN gcc -O2 -Wall -Wextra courier.c -o courier

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server netcat-openbsd coreutils \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /usr/local/bin/case-shell player \
 && echo 'player:player' | chpasswd \
 && mkdir -p /run/sshd /etc/copper
COPY --from=build /build/courier /usr/local/bin/courier
COPY src/case-shell src/entrypoint.sh src/healthcheck.sh /usr/local/bin/
RUN chown root:root /usr/local/bin/courier \
 && chmod 4755 /usr/local/bin/courier \
 && chmod 755 /usr/local/bin/case-shell /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh
EXPOSE 22
HEALTHCHECK --interval=15s --timeout=4s --retries=3 CMD /usr/local/bin/healthcheck.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Минимальные привилегии для jury (root: задача решается легитимной эскалацией внутри контейнера)
LABEL org.innoctf.runtime=root
