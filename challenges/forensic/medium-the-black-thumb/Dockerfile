FROM python:3.12-slim
WORKDIR /app
# Base-образ 256 MiB собирается в образе: MBR + P1 ext4 (дом курьера) +
# приманка (fake ext2 «recovery») + скрытый ext2-том (sealed.bin — нули;
# ZIP из живого флага патчится в него runtime-ом, server.py).
# Декор-медиа (~100 МБ: Commons/SoundHelix/test-videos) скачивается
# отдельным слоем — он кэшируется, и падение сети видно на своём шаге.
COPY src/build_image.py src/download_media.py .
RUN apt-get update && apt-get install -y --no-install-recommends e2fsprogs zip && rm -rf /var/lib/apt/lists/*
RUN python3 download_media.py /srv/media-src
RUN python3 build_image.py --out /srv/base --media-dir /srv/media-src --verify
# сервис — non-root (ctf): пишет /srv/public, /srv/base только чтение
RUN useradd -u 10001 -m ctf && mkdir -p /srv/public && chown ctf /srv/public \
    && chown -R root:root /srv/base && chmod 755 /srv/base && chmod 644 /srv/base/*
COPY src/server.py .
EXPOSE 8080
# start-period: runtime патчит 256 MiB и гзипит ~104 МБ медиа — даём запас
HEALTHCHECK --interval=15s --timeout=4s --retries=3 --start-period=240s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"
USER ctf
CMD ["python", "server.py"]

# Минимальные привилегии для jury (writable: non-root USER, rw rootfs — флаг материализуется на старте)
LABEL org.innoctf.runtime=writable
