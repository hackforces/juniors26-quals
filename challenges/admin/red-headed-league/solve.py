#!/usr/bin/env python3
"""Решение «The Red-Headed League» (admin/easy).

Механика: SSH user player (пароль player), оболочка — case-shell: `help`
перечисляет только имена команд, аргументы не подсказываются; всё, что не
точный whitelist-вариант, отвечает «argument is not available».
  1. `ss` — находим loopback-only «стол справок» на 127.0.0.1:4587.
  2. `nc 127.0.0.1 4587` — баннер стола называет /etc/red/card.
  3. `cat /etc/red/card` — номер дела (sha256(флаг)[:16]).
  4. `nc 127.0.0.1 4587` — предъявляем номер столу, получаем флаг.

Запуск:  python3 solve.py [host] [port]      (по умолчанию 127.0.0.1 13409)
Нужны: ssh, sshpass.
"""

import re
import select
import subprocess
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = sys.argv[2] if len(sys.argv) > 2 else "13409"
USER, PASSWORD = "player", "player"
FLAG_RE = re.compile(r"(?i)\b[a-z0-9_]{2,32}\{[^{}\s]{4,}\}")
SSH_BASE = [
    "sshpass", "-p", PASSWORD,
    "ssh", "-q", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
    "-p", PORT, f"{USER}@{HOST}",
]


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


def send(proc: subprocess.Popen, line: str) -> None:
    proc.stdin.write((line + "\n").encode())
    proc.stdin.flush()


def main() -> int:
    proc = subprocess.Popen(SSH_BASE, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    try:
        time.sleep(2.0)
        # Шаг 0: шелл не выдаёт готовых аргументов — help перечисляет только
        # имена команд, а любая команда с недопустимыми аргументами отвечает
        # ровно «argument is not available» (без оракула для перебора).
        send(proc, "help")
        out = drain(proc, timeout=5)
        if "/etc/red/card" in out or "4587" in out:
            print(f"[-] help раскрывает аргументы команд:\n{out}", file=sys.stderr)
            return 1
        for probe in ("cat /etc/passwd", "nc 127.0.0.1 9999"):
            send(proc, probe)
            out = drain(proc, timeout=5)
            if "argument is not available" not in out:
                print(f"[-] {probe}: чужие аргументы не отвергнуты:\n{out}", file=sys.stderr)
                return 1
        # Шаг 1: найти стол справок (диагностика ss).
        send(proc, "ss")
        out = drain(proc, timeout=5)
        if ":4587" not in out:
            print(f"[-] стол справок не найден через ss:\n{out}", file=sys.stderr)
            return 1
        # Шаг 2: номер дела.
        send(proc, "cat /etc/red/card")
        out = drain(proc, timeout=5)
        m = re.search(r"\b[0-9a-f]{16}\b", out)
        if not m:
            print(f"[-] номер дела не прочитан:\n{out}", file=sys.stderr)
            return 1
        number = m.group(0)
        print(f"[+] номер дела: {number}")
        # Шаг 3: предъявить номер столу.
        send(proc, "nc 127.0.0.1 4587")
        out = drain(proc, timeout=8, wait_for="number: ")
        send(proc, number)
        out = drain(proc, timeout=10)

        fm = FLAG_RE.search(out)
        if not fm:
            print(f"[-] флаг не получен:\n{out}", file=sys.stderr)
            return 1
        print(fm.group(0))
        return 0
    finally:
        proc.kill()


if __name__ == "__main__":
    sys.exit(main())
