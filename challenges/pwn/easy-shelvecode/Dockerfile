# shelvecode: сборка бинарника и easy-shelvecode-files.zip из тех же исходников, затем
# лёгкий рантайм (amd64 — эксплойт рассчитан на x86-64 layout арены).
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev zip && rm -rf /var/lib/apt/lists/*
COPY src/sandbox.c /tmp/sandbox.c
RUN gcc -std=c11 -Wall -Wextra -Wpedantic -O2 -fPIE -pie \
      -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now \
      /tmp/sandbox.c -o /tmp/shelvecode-sandbox \
    && strip --strip-all /tmp/shelvecode-sandbox \
    && mkdir -p /handout /www \
    && cp /tmp/shelvecode-sandbox /handout/shelvecode-sandbox \
    && cd /handout && zip -q -X /www/easy-shelvecode-files.zip shelvecode-sandbox

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends socat util-linux busybox && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 ctf
COPY --from=build /tmp/shelvecode-sandbox /usr/local/bin/shelvecode-sandbox
COPY --from=build /www/easy-shelvecode-files.zip /www/easy-shelvecode-files.zip
COPY src/entrypoint.sh src/healthcheck.sh /opt/challenge/
RUN chmod 755 /opt/challenge/*.sh /usr/local/bin/shelvecode-sandbox
EXPOSE 6767 31338
HEALTHCHECK --interval=15s --timeout=4s --retries=3 CMD /opt/challenge/healthcheck.sh
# флаг пишется в /run/case/flag из env CTF_FLAG на старте; сервис работает от ctf
ENTRYPOINT ["/opt/challenge/entrypoint.sh"]

# Минимальные привилегии для jury (writable: non-root USER, rw rootfs — флаг материализуется на старте)
LABEL org.innoctf.runtime=writable
