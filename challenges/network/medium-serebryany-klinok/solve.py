#!/usr/bin/env python3
"""Решение «Серебряный клинок» (network/medium).

Скачиваем night.pcap с живого инстанса (или берём локальный файл), собираем
нумерованные DNS-метки `<nn>-<data>.silver.baker` по порядку (каждая метка
встречается в запросе; ответ эхом сжимает вопрос указателем, но на всякий
случай дедуплицируем), склеиваем Base32 и декодируем.

Идея решения по шагам:
1. Дамп — ночная сессия справочника (HTTP-портал, TLS-подобный аплинк, ICMP,
   декой-DNS A/AAAA/MX/TXT/PTR). Экзофилтрация спрятана в серии UDP/DNS-запросов
   (порт 53) с метками <nn>-<data>.silver.baker.
2. Данные — в самих именах запросов (subdomain-экзофилтрация); ответы NXDOMAIN
   не важны, nn — двузначный порядковый номер куска.
3. Регэксп идёт по сырым байтам pcap без парсера: [\x00-\x3f] — байт длины
   DNS-метки (<=63), \x06silver\x05baker — кодирование имени длинами; числовой
   префикс «nn-» отсекает декои той же зоны (patrol-report и т.п.).
4. Ответ эхом сжимает вопрос указателем, поэтому каждая метка встречается
   дважды — дедуплицируем и собираем куски по порядку номеров.
5. Склеенное — Base32-текст ([a-z2-7] в нижнем регистре), выравниваем '='
   до кратности 8, b32decode даёт флаг.

Запуск:  python3 solve.py [base_url | путь_к_night.pcap]
"""

import base64
import re
import sys
import urllib.request
from pathlib import Path

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13418/download/night.pcap"


def main() -> int:
    if TARGET.startswith("http"):
        data = urllib.request.urlopen(TARGET, timeout=15).read()
    else:
        data = Path(TARGET).read_bytes()
    parts, seen = [], set()
    # Первая группа — «nn-» (номер куска), вторая — Base32-данные метки.
    for label in re.findall(rb"[\x00-\x3f](\d\d-[a-z2-7]+)\x06silver\x05baker", data):
        # Дедупликация: вопрос дублируется в ответе сжатием-указателем,
        # каждая метка должна попасть в конвейер ровно один раз.
        if label not in seen:
            seen.add(label)
            parts.append(label.split(b"-", 1)[1])
    if not parts:
        print("[-] DNS-метки silver.baker не найдены", file=sys.stderr)
        return 1
    # Base32 (не Base64!): алфавит DNS-меток — только [a-z2-7]; b32decode
    # ждёт верхний регистр и длину, кратную 8, — приводим и добиваем «=».
    s = b"".join(parts).upper()
    s += b"=" * (-len(s) % 8)
    flag = base64.b32decode(s).decode()
    # Санити-чек формата флага: сразу видно, если куски собраны не по порядку.
    if not re.fullmatch(r"(?i)[a-z0-9_]{2,32}\{[^{}\s]{4,}\}", flag):
        print(f"[-] восстановлено нечто некорректное: {flag!r}", file=sys.stderr)
        return 1
    print(flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
