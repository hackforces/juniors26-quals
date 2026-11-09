FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev zip && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/challenge.c .
RUN gcc challenge.c -o carbuncle -O0 -fno-omit-frame-pointer -fno-stack-protector -no-pie -Wl,-z,norelro \
    && mkdir -p /handout /www \
    && cp carbuncle /handout/carbuncle && chmod 755 /handout/carbuncle \
    && cd /handout && zip -q -X /www/easy-the-blue-carbuncle-files.zip carbuncle

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends socat util-linux busybox && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 ctf
COPY --from=build /build/carbuncle /opt/challenge/carbuncle
COPY --from=build /www/easy-the-blue-carbuncle-files.zip /www/easy-the-blue-carbuncle-files.zip
COPY src/entrypoint.sh src/healthcheck.sh /opt/challenge/
RUN chmod 755 /opt/challenge/*.sh /opt/challenge/carbuncle
EXPOSE 31337 31338
HEALTHCHECK --interval=15s --timeout=4s --retries=3 CMD /opt/challenge/healthcheck.sh
ENTRYPOINT ["/opt/challenge/entrypoint.sh"]

# Минимальные привилегии для jury (writable: non-root USER, rw rootfs — флаг материализуется на старте)
LABEL org.innoctf.runtime=writable
