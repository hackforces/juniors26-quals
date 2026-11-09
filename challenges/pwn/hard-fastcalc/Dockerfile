# fastcalc: web (Flask-калькулятор) и vm (C-ВМ на unix-сокете) — два таргета
# одного Dockerfile; compose собирает web как `challenge` плюс сервис vm.
FROM debian:bookworm-slim AS vm-build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY src/vm/vm_server.c /tmp/vm_server.c
RUN gcc -std=c11 -Wall -Wextra -Wpedantic -O2 -fPIE -pie \
      -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now \
      /tmp/vm_server.c -o /tmp/fastcalc-vm \
    && strip --strip-all /tmp/fastcalc-vm

FROM python:3.12-slim AS web
RUN useradd -m -u 10001 fastcalc
WORKDIR /app
COPY src/web/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY src/web /app
# заводская прошивка генерируется при сборке из format.py, флаг в неё не попадает
COPY src/firmware/format.py /app/format.py
RUN python3 /app/format.py && rm /app/format.py \
    && mkdir -p /var/lib/fastcalc /run/fastcalc \
    && chown -R fastcalc:fastcalc /var/lib/fastcalc /run/fastcalc /app
USER fastcalc
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    DEFAULT_FIRMWARE=/app/default.fw STATE_DIR=/var/lib/fastcalc \
    VM_SOCKET=/run/fastcalc/vm.sock
EXPOSE 5000
HEALTHCHECK --interval=15s --timeout=4s --retries=3 \
    CMD python3 -c "import urllib.request as u; u.urlopen('http://127.0.0.1:5000/', timeout=3)"
CMD ["python3", "app.py"]

# Минимальные привилегии для jury (writable: non-root USER, rw rootfs — флаг материализуется на старте)
LABEL org.innoctf.runtime=writable

FROM debian:bookworm-slim AS vm
RUN apt-get update && apt-get install -y --no-install-recommends util-linux && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 fastcalc \
    && mkdir -p /run/fastcalc /run/case \
    && chown -R fastcalc:fastcalc /run/fastcalc /run/case
COPY --from=vm-build /tmp/fastcalc-vm /usr/local/bin/fastcalc-vm
COPY src/vm/entrypoint.sh /opt/challenge/entrypoint.sh
RUN chmod 755 /opt/challenge/entrypoint.sh
HEALTHCHECK --interval=15s --timeout=4s --retries=3 CMD test -S /run/fastcalc/vm.sock
# флаг пишется в /run/case/flag из env CTF_FLAG на старте; процесс падает до fastcalc
ENTRYPOINT ["/opt/challenge/entrypoint.sh"]

# Минимальные привилегии для jury (writable: non-root USER, rw rootfs — флаг материализуется на старте)
LABEL org.innoctf.runtime=writable
