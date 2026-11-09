FROM python:3.12-slim
WORKDIR /app
COPY src/gen.py src/server.py .
RUN useradd -u 10001 -m ctf && mkdir -p /srv/public && chown ctf /srv/public
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=4s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"
USER ctf
CMD ["python", "server.py"]

# Минимальные привилегии для jury (writable: non-root USER, rw rootfs — флаг материализуется на старте)
LABEL org.innoctf.runtime=writable
