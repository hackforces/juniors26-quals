# retro-heap: сборка бинарника и retro-heap-files.zip, затем лёгкий рантайм (amd64).
FROM --platform=linux/amd64 ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev zip && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/chal.c ./
COPY src/handout_run.sh run.sh
RUN cc -O2 -Wall -Wextra -fPIE -pie -fstack-protector-strong -Wl,-z,relro,-z,now -o /chal chal.c && \
    mkdir -p /handout /www && \
    cp /chal /handout/chal && \
    cp /lib/x86_64-linux-gnu/libc.so.6 /handout/libc.so.6 && \
    cp /lib64/ld-linux-x86-64.so.2 /handout/ld-linux-x86-64.so.2 && \
    cp run.sh /handout/run.sh && \
    chmod 755 /handout/chal /handout/run.sh /handout/ld-linux-x86-64.so.2 && \
    cd /handout && zip -q -X -r /www/retro-heap-files.zip .

FROM --platform=linux/amd64 ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends socat python3 && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 pwn && chmod 711 /home/pwn
COPY --from=build /chal /srv/chal
COPY --from=build /www/retro-heap-files.zip /www/retro-heap-files.zip
COPY src/server.py /srv/server.py
COPY src/run_chal.sh /run_chal.sh
COPY src/entrypoint.sh /entrypoint.sh
RUN chmod 755 /run_chal.sh /entrypoint.sh /srv/chal
WORKDIR /srv
EXPOSE 8008 1337
HEALTHCHECK --interval=15s --timeout=4s --retries=3 \
    CMD python3 -c "import socket; socket.create_connection(('127.0.0.1', 1337), 2).close()"
# флаг пишется в /flag.txt из env CTF_FLAG на старте; сервисы работают от пользователя pwn
ENTRYPOINT ["/entrypoint.sh"]

# Минимальные привилегии для jury (root: задача решается легитимной эскалацией внутри контейнера)
LABEL org.innoctf.runtime=root
