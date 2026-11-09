FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev zip && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/challenge.c .
RUN gcc challenge.c -o valley -O0 -fno-omit-frame-pointer -fPIE -pie -fstack-protector-all -Wl,-z,relro,-z,now \
    && mkdir -p /handout /www \
    && cp valley /handout/valley && chmod 755 /handout/valley \
    && cd /handout && zip -q -X /www/hard-the-valley-of-fear-files.zip valley

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends socat util-linux busybox && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 ctf
COPY --from=build /build/valley /opt/challenge/valley
COPY --from=build /www/hard-the-valley-of-fear-files.zip /www/hard-the-valley-of-fear-files.zip
COPY src/entrypoint.sh src/healthcheck.sh /opt/challenge/
RUN chmod 755 /opt/challenge/*.sh /opt/challenge/valley
EXPOSE 31337 31338
HEALTHCHECK --interval=15s --timeout=4s --retries=3 CMD /opt/challenge/healthcheck.sh
ENTRYPOINT ["/opt/challenge/entrypoint.sh"]

# Минимальные привилегии для jury (writable: non-root USER, rw rootfs — флаг материализуется на старте)
LABEL org.innoctf.runtime=writable
