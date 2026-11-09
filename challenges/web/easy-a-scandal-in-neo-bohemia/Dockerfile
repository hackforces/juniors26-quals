FROM python:3.12-alpine
WORKDIR /app
COPY src/server.py /app/server.py
COPY src/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && adduser -D -u 10001 ctf
USER ctf
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=3 CMD python /app/healthcheck.py
COPY src/healthcheck.py /app/healthcheck.py
ENTRYPOINT ["/entrypoint.sh"]

# Минимальные привилегии для jury (writable: non-root USER, rw rootfs — флаг материализуется на старте)
LABEL org.innoctf.runtime=writable
