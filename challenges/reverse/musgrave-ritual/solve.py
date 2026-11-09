#!/usr/bin/env python3
"""Эксплойт для «The Musgrave Ritual»: скачать musgrave-ritual.zip у живого инстанса,
разобрать ritual_device.py и обратить преобразование.

Верификатор перемешивает байты флага по hash-порядку и применяет
stateful-преобразование (ROL + XOR seed + XOR state от предыдущего байта).
Разворот: восстановить порядок, затем слева направо инвертировать
поворот и XOR.

Запуск:  python3 solve.py [url]   (по умолчанию http://127.0.0.1:13429)
"""

import ast
import hashlib
import io
import re
import sys
import urllib.request
import zipfile

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13429"
zip_url = url.rstrip("/") + "/download/musgrave-ritual.zip"

with urllib.request.urlopen(zip_url, timeout=15) as r:
    data = r.read()

with zipfile.ZipFile(io.BytesIO(data)) as z:
    s = z.read("ritual_device.py").decode()

seed = ast.literal_eval(re.search(r"SEED = (.+)", s).group(1))
target = ast.literal_eval(re.search(r"TARGET = (.+)", s).group(1))


def ror(x, n):
    return ((x >> n) | (x << (8 - n))) & 255


order = sorted(
    range(len(target)),
    key=lambda i: hashlib.sha256(seed + i.to_bytes(2, "big")).digest(),
)
stage = [0] * len(target)
for position, index in enumerate(order):
    stage[index] = target[position]

out = []
previous = 0
for i, value in enumerate(stage):
    state = (previous * 13 + i * 29 + 7) & 255
    byte = ror(value, (i % 5) + 1) ^ seed[i % 8] ^ state
    out.append(byte)
    previous = byte
print(bytes(out).decode())
