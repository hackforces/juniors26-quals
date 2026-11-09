FROM python:3.12-slim

# No toolchain needed: lupa ships manylinux wheels for cp312.
WORKDIR /app

COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd -m -u 10001 ctf

COPY src/app.py src/judge_worker.py ./
COPY src/templates/ ./templates/
COPY src/healthcheck.py /app/healthcheck.py

USER ctf
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=4s --retries=3 \
    CMD python /app/healthcheck.py
CMD ["python", "app.py"]

# Минимальные привилегии для jury (writable: non-root USER, rw rootfs — флаг материализуется на старте)
LABEL org.innoctf.runtime=writable
