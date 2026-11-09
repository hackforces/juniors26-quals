FROM python:3.12-alpine
WORKDIR /app
COPY src/ /app/
RUN chmod +x /app/entrypoint.sh && adduser -D -u 10001 ctf
USER ctf
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=3 CMD python /app/healthcheck.py
ENTRYPOINT ["/app/entrypoint.sh"]

# Минимальные привилегии для jury (writable: non-root USER, rw rootfs — флаг материализуется на старте)
LABEL org.innoctf.runtime=writable
