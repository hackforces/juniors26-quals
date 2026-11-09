#!/usr/bin/env python3
"""Эксплойт для «Дела о скандале в нео-Богемии».

Главная страница выглядит обычной, но подключает /assets/client.js, в
котором лежит window.caseMemo = base64(CTF_FLAG). Скрипт выполняется у
клиента и «помнит больше, чем показывает» — достаточно открыть исходник.

Запуск:  python3 solve.py [url]   (по умолчанию http://127.0.0.1:13434)
"""

import base64
import re
import sys
import urllib.request

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13434"

with urllib.request.urlopen(url.rstrip("/") + "/assets/client.js", timeout=15) as r:
    js = r.read().decode()

memo = re.search(r"window\.caseMemo = '([^']+)'", js).group(1)
print(base64.b64decode(memo).decode())
