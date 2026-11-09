FROM python:3.12-slim
RUN pip install --no-cache-dir cryptography \
    && useradd -m -u 10001 ctf
WORKDIR /app
COPY src/ /app/src/
COPY solve.py /app/solve.py
RUN chmod 755 /app/src/entrypoint.sh && mkdir -p /app/public && chown -R ctf:ctf /app
USER ctf
ENV PORT=8089 \
    HANDOUT_PATH=/app/blockpost.zip \
    PYTHONPATH=/app/src
EXPOSE 8089
# при старте: генерация blockpost.zip из CTF_FLAG + self-check солвером (см. src/entrypoint.sh)
HEALTHCHECK --interval=15s --timeout=4s --start-period=120s --retries=5 \
    CMD python -c "import urllib.request as u,sys; sys.exit(0 if u.urlopen('http://127.0.0.1:8089/', timeout=3).status == 200 else 1)"
ENTRYPOINT ["/app/src/entrypoint.sh"]

# Минимальные привилегии для jury (writable: non-root USER, rw rootfs — флаг материализуется на старте)
LABEL org.innoctf.runtime=writable
