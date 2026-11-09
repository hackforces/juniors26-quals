#!/usr/bin/env python3
"""Эксплойт для «The Second Stain»: скачать second-stain.zip у живого инстанса,
разобрать байткод last_log.vm и обратить преобразование.

Семантика из watch_runtime.py: повторяющиеся 4-байтовые записи
(0x10 <encoded>, 0x20 <index>), где encoded = plain ^ ((index*17+31)&255).

Запуск:  python3 solve.py [url]   (по умолчанию http://127.0.0.1:13430)
"""

import io
import sys
import urllib.request
import zipfile

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13430"
zip_url = url.rstrip("/") + "/download/second-stain.zip"

with urllib.request.urlopen(zip_url, timeout=15) as r:
    data = r.read()

with zipfile.ZipFile(io.BytesIO(data)) as z:
    p = z.read("last_log.vm")

out = []
i = 0
while p[i] != 0xFF:
    assert p[i] == 0x10
    value = p[i + 1]
    assert p[i + 2] == 0x20
    pos = p[i + 3]
    out.append(value ^ ((pos * 17 + 31) & 255))
    i += 4
print(bytes(out).decode())
