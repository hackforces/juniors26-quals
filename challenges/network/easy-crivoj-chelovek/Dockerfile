FROM python:3.12-alpine
WORKDIR /app
COPY src/ /app/src/
RUN adduser -D -u 10001 ctf
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"
USER ctf
CMD ["python", "/app/src/server.py"]

# Минимальные привилегии для jury (writable: non-root USER, rw rootfs — флаг материализуется на старте)
LABEL org.innoctf.runtime=writable
