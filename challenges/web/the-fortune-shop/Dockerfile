FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd -m -u 10001 ctf

COPY src/app ./app
COPY src/healthcheck.py /app/healthcheck.py
COPY src/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /app/data \
    && chown ctf:ctf /app/data

USER ctf
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=4s --retries=3 \
    CMD python /app/healthcheck.py
ENTRYPOINT ["/entrypoint.sh"]

# Минимальные привилегии для jury (writable: non-root USER, rw rootfs — флаг материализуется на старте)
LABEL org.innoctf.runtime=writable
