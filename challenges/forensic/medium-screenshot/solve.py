#!/usr/bin/env python3
"""Решение «Screenshot» (forensic/medium).

Этап 1 (восстановление экрана из ПЭМИН-записи) делается в TempestSDR по
WALKTHROUGH.md — код запуска читается с восстановленного растра. Этап 2 —
этот скрипт: подключается к «замку», отдаёт код и печатает флаг.

Запуск:  python3 solve.py [--code CODE] [host] [port]
         (по умолчанию 127.0.0.1 13446; код по умолчанию — с записи)

Идея решения (этап 2, этот скрипт):
1. Код запуска читается с экрана, восстановленного из ПЭМИН-записи в
   TempestSDR (этап 1, вручную по WALKTHROUGH.md); код — не флаг, а ключ
   ко второму этапу, в самой записи его строкой нет.
2. Подключиться к «замку микроволновки» и дождаться баннера-приглашения —
   сервис ждёт ввод именно после него.
3. Отправить код одной строкой (18 символов, регистр важен).
4. Дочитать ответ до закрытия соединения или таймаута.
5. Выцепить флаг шаблоном NAME{...} из текста ответа сервиса.
"""

import argparse
import re
import socket
import sys

DEFAULT_CODE = "RiLEBO4XySIkdt$FdT"  # строка, читаемая с восстановленного экрана


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("port", nargs="?", type=int, default=13446)
    parser.add_argument("--code", default=DEFAULT_CODE, help="код запуска с экрана (18 символов)")
    args = parser.parse_args()

    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        sock.settimeout(10)
        banner = sock.recv(1024)
        print(banner.decode("utf-8", "replace"), end="")
        # строковый протокол: код — одна строка, завершённая \n
        sock.sendall(args.code.encode() + b"\n")
        response = bytearray()
        # читаем до таймаута или EOF: сервис не закрывает соединение сразу
        while True:
            try:
                chunk = sock.recv(1024)
            except socket.timeout:
                break
            if not chunk:
                break
            response.extend(chunk)
    text = response.decode("utf-8", "replace")
    print(text, end="")

    # шаблон флага: имя до 32 символов, затем {...} без вложенных скобок
    match = re.search(r"([A-Za-z0-9_]{1,32}\{[^{}]{4,}\})", text)
    if match:
        print("[+] Флаг:", match.group(1))
        return 0
    print("[-] Флаг не получен: замок код не принял (проверьте код с экрана)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
