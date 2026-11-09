# mini-vm: сборка VM-блоба и статического бинарника, затем лёгкий рантайм.
FROM --platform=linux/amd64 alpine:3.20 AS build
RUN apk add --no-cache build-base python3
WORKDIR /build
COPY src/ src/
# SEED (опционально) меняет S-box/константы P — это не секрет и в рантайм не попадает
ARG SEED=
RUN python3 src/gen_vm.py $SEED && \
    mkdir -p /out && \
    cc -O2 -Wall -static -s -o /out/minivm src/chal.c src/sha256.c -I src && \
    cp /out/minivm ./minivm && \
    CHAL_BIN=./minivm python3 src/make_public.py && \
    cp public/mini-vm-files.zip /out/mini-vm-files.zip

FROM python:3.12-slim
RUN useradd -m -u 10001 ctf
COPY --from=build /out/minivm /chal.bin
COPY --from=build /out/mini-vm-files.zip /mini-vm-files.zip
COPY src/server.py /srv/server.py
WORKDIR /srv
USER ctf
ENV CHAL_PATH=/chal.bin \
    HANDOUT_PATH=/mini-vm-files.zip \
    TIME_LIMIT=20 \
    ROUNDS=1 \
    PORT_HTTP=8000 \
    PORT_NC=1337
EXPOSE 8000 1337
HEALTHCHECK --interval=15s --timeout=4s --retries=3 \
    CMD python -c "import socket; socket.create_connection(('127.0.0.1', 1337), 2).close()"
CMD ["python3", "-u", "/srv/server.py"]

# Минимальные привилегии для jury (writable: non-root USER, rw rootfs — флаг материализуется на старте)
LABEL org.innoctf.runtime=writable
