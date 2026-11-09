#!/usr/bin/env python3
"""Решение «Кривой человек» (network/easy).

Скачиваем scene.pcap с живого инстанса (или берём локальный файл) и достаём
флаг из тела POST /watson-note — единственного payload с фигурными скобками
среди фонового трафика панели.

Запуск:  python3 solve.py [base_url | путь_к_scene.pcap]
"""

import re
import sys
import urllib.request
from pathlib import Path

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13416/download/scene.pcap"
FLAG_RE = re.compile(rb"(?i)\b[a-z0-9_]{2,32}\{[^{}\s]{4,}\}")


def main() -> int:
    if TARGET.startswith("http"):
        data = urllib.request.urlopen(TARGET, timeout=15).read()
    else:
        data = Path(TARGET).read_bytes()
    hits = FLAG_RE.findall(data)
    if len(hits) != 1:
        print(f"[-] ожидался ровно один флаг в scene.pcap, найдено {len(hits)}", file=sys.stderr)
        return 1
    print(hits[0].decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
