# screenshot: сетевой замок микроволновки (nc), флаг только из env;
# ПЭМИН-запись монитора раздаётся отдельно (public/, git lfs).
FROM python:3.12-slim

WORKDIR /srv
COPY src/server.py /srv/server.py

ENV PORT=7777
USER nobody
EXPOSE 7777
HEALTHCHECK --interval=15s --timeout=4s --retries=3 \
    CMD python3 -c "import socket; s=socket.create_connection(('127.0.0.1', 7777), 3); s.sendall(b'x'); s.recv(16)" || exit 1
# флаг приходит env CTF_FLAG (алиас FLAG); код на экране записи статичен
LABEL org.innoctf.runtime=writable
ENTRYPOINT ["python3", "/srv/server.py"]
