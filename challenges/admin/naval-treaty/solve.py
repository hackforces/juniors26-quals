#!/usr/bin/env python3
"""Решение «The Naval Treaty» (admin/hard).

Механика: SSH user player (пароль player), оболочка — ограниченный case-shell.
  1. `read /etc/machine-id`, `read /etc/treaty/slot` и чтение
     `/usr/local/bin/derive-pass.sh` раскрывают деривацию пароля PKCS#12:
     sha256("<machine-id>:<slot>")[:20].
  2. `extract <pass>` восстанавливает клиентскую печать (TLS-сертификат).
  3. `connect` поднимает mTLS-клиента к архиву на 127.0.0.1:9443,
     командой `FETCH 2050.06.17-04` получаем флаг (эпоха — из `journal`).

Запуск:  python3 solve.py [host] [port]      (по умолчанию 127.0.0.1 13407)
Нужны: ssh, sshpass.

TLS-обёртка (ssh поверх openssl s_client): экспортируйте
  export SOLVE_SSH_OPTS='-o "ProxyCommand=openssl s_client -quiet -connect <host>:443 -servername <host>"'
(внутренние кавычки обязательны — опции парсятся через shlex.split).
"""

import hashlib
import os
import re
import select
import shlex
import subprocess
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = sys.argv[2] if len(sys.argv) > 2 else "13407"
USER, PASSWORD = "player", "player"
# Инфраструктура может выдать флаг с любым префиксом (InnoCTF{...}, flag{...}).
FLAG_RE = re.compile(r"(?i)\b(?:innoctf|ctf|flag)\{[^}]+\}")
SSH_BASE = [
    "sshpass", "-p", PASSWORD,
    "ssh", "-q", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
    "-p", PORT, f"{USER}@{HOST}",
] + shlex.split(os.environ.get("SOLVE_SSH_OPTS", ""))


def drain(proc: subprocess.Popen, timeout: float, wait_for: str = "") -> str:
    out = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        ready, _, _ = select.select([proc.stdout], [], [], 0.5)
        for fd in ready:
            chunk = fd.read1(65536)
            if chunk:
                out += chunk
        text = out.decode(errors="replace")
        if wait_for and wait_for in text:
            break
        if FLAG_RE.search(text):
            break
    return out.decode(errors="replace")


def session(retries: int = 3) -> subprocess.Popen:
    """Стартуем ssh; TLS-туннель иногда рвётся на хендшейке — ретраим."""
    for _ in range(retries):
        s = subprocess.Popen(SSH_BASE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL)
        try:
            # ждём реальный промпт терминала, а не фиксированную паузу
            if "treaty> " in drain(s, timeout=20, wait_for="treaty> "):
                return s
        except BrokenPipeError:
            pass
        s.kill()
        time.sleep(2)
    raise RuntimeError("ssh session failed: no treaty prompt (проверьте SOLVE_SSH_OPTS)")


def send(proc: subprocess.Popen, line: str) -> None:
    proc.stdin.write((line + "\n").encode())
    proc.stdin.flush()


def main() -> int:
    # Шаг 1: собираем machine-id и slot из терминала.
    s = session()
    send(s, "read /etc/machine-id")
    time.sleep(1.0)
    send(s, "read /etc/treaty/slot")
    out = drain(s, timeout=6)
    # значение может прийти и с начала захвата (промпт потреблён в session()),
    # и инлайн после промпта — допускаем обе формы
    machine_id = re.search(r"(?:^|treaty> )([0-9a-z]{16,40})\s*$", out, re.MULTILINE)
    slot = re.search(r"(?:^|treaty> )(case-\d+)\s*$", out, re.MULTILINE)
    if not machine_id or not slot:
        print(f"[-] не удалось прочитать machine-id/slot:\n{out}", file=sys.stderr)
        s.kill()
        return 1
    mid = machine_id.group(1).strip()
    slt = slot.group(1).strip()
    print(f"[+] machine-id={mid} slot={slt}")
    # Деривация из /usr/local/bin/derive-pass.sh: sha256(machine_id:slot)[:20]
    password = hashlib.sha256(f"{mid}:{slt}".encode()).hexdigest()[:20]
    print(f"[+] пароль печати: {password}")

    # Шаг 2: восстановить печать.
    send(s, f"extract {password}")
    out = drain(s, timeout=6)
    if "client seal restored" not in out:
        print(f"[-] печать не восстановлена:\n{out}", file=sys.stderr)
        s.kill()
        return 1

    # Шаг 3: подключиться и забрать бюллетень.
    send(s, "connect")
    out = drain(s, timeout=10, wait_for="archive> ")
    send(s, "FETCH 2050.06.17-04")
    out = drain(s, timeout=10)
    s.kill()

    fm = FLAG_RE.search(out)
    if not fm:
        print(f"[-] флаг не получен:\n{out}", file=sys.stderr)
        return 1
    print(fm.group(0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
