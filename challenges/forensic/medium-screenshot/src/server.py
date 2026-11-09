#!/usr/bin/env python3
"""
screenshot — сетевой замок микроволновки (stdlib only).

При подключении (nc) спрашивает код запуска микроволновки. Код тот же, что
виден на перехваченном экране босса (восстанавливается из ПЭМИН-записи в
public/). Верный код -> сервис отдаёт флаг. Флаг берётся из переменной
окружения CTF_FLAG (алиас FLAG) и нигде, кроме окружения, не хранится.
"""

import os
import re
import socketserver

# код запуска — тот, что «нарисован» на экране босса записью public/.
# Запись статичная, поэтому код фиксирован; менять его можно только вместе
# с перевыпуском хендаута.
CODE = os.environ.get("CODE", "RiLEBO4XySIkdt$FdT")
FLAG = os.environ.get("CTF_FLAG") or os.environ.get("FLAG") or ""
PORT = int(os.environ.get("PORT", "7777"))
ATTEMPTS = 3

# флаг любого формата prefix{payload} — платформа присылает CTF_FLAG целиком
if not re.fullmatch(r"[A-Za-z0-9_]{1,32}\{[^{}]{4,}\}", FLAG):
    raise SystemExit("CTF_FLAG/FLAG must be set in prefix{payload} format")

BANNER = (
    "=== MICROWAVE LOCK CONTROLLER v1.3 ===\n"
    "Босс закрыл микроволновку на замок. Без кода запуска оладушки остаются холодными.\n\n"
).encode("utf-8")
PROMPT = "Коды запуска микроволновки: ".encode()
DENY = "Доступ запрещён. Оладушки остаются холодными.\n".encode()
GRANT = "Замок снят! Разогреваем оладушки. Ваш флаг: {}\n".format


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(60)
        self.request.sendall(BANNER)
        for left in range(ATTEMPTS, 0, -1):
            self.request.sendall(PROMPT)
            try:
                data = self.request.recv(256)
            except OSError:
                return
            if not data:
                return
            guess = data.decode("utf-8", "replace").strip()
            if guess == CODE:
                self.request.sendall(GRANT(FLAG).encode())
                return
            self.request.sendall(DENY)
            if left > 1:
                self.request.sendall(f"Осталось попыток: {left - 1}\n".encode())
        self.request.sendall("Попытки исчерпаны. Пока, оладушки.\n".encode("utf-8"))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    with Server(("0.0.0.0", PORT), Handler) as srv:
        print(f"[nc] listening on :{PORT}", flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
