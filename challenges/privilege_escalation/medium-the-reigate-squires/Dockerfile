FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/case_reader.c .
RUN gcc -O2 case_reader.c -o case-reader
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server libcap2-bin && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/bash player && echo 'player:player' | chpasswd && mkdir -p /run/sshd
COPY --from=build /build/case-reader /usr/local/bin/case-reader
COPY src/entrypoint.sh src/healthcheck.sh /usr/local/bin/
RUN chown root:root /usr/local/bin/case-reader && chmod 0755 /usr/local/bin/case-reader \
 && setcap cap_dac_override+ep /usr/local/bin/case-reader && chmod 755 /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh
EXPOSE 22
HEALTHCHECK --interval=15s --timeout=4s --retries=3 CMD /usr/local/bin/healthcheck.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Минимальные привилегии для jury (root: задача решается легитимной эскалацией внутри контейнера)
LABEL org.innoctf.runtime=root
