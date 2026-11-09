#!/usr/bin/env python3
"""Эксплойт для «The Empty House»: скачать empty-house.zip у живого инстанса,
разобрать pocket_computer.py и применить однобайтовый XOR (0x5A).

Запуск:  python3 solve.py [url]   (по умолчанию http://127.0.0.1:13428)
"""

import ast
import io
import re
import sys
import urllib.request
import zipfile

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13428"
zip_url = url.rstrip("/") + "/download/empty-house.zip"

with urllib.request.urlopen(zip_url, timeout=15) as r:
    data = r.read()

with zipfile.ZipFile(io.BytesIO(data)) as z:
    source = z.read("pocket_computer.py").decode()

blob = ast.literal_eval(re.search(r"blob = (.+)", source).group(1))
print("".join(chr(x ^ 0x5A) for x in blob))
