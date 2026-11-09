#!/usr/bin/env python3
"""Решатель «Давно с Востока?» (osint/medium).

Чистый OSINT: инстанса нет, задача решается внешними источниками. Скрипт
делает два режима:

  python3 solve.py --answer 'Hoa Lo Prison'  # сверить свой ответ
  python3 solve.py                           # последний шаг автоматом (нужен интернет:
                                             # координаты комплекса из Википедии)
"""

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request

ANSWER = "Hoa Lo Prison"
FLAG = "CTF{Hoa Lo Prison}"
WIKI_TITLE = "Hỏa Lò Prison"


ACCEPTED = ("Hoa Lo Prison", "Hỏa Lò Prison", "Maison Centrale", "Hanoi Hilton", "Hoa Lo")  # канон и общепринятые синонимы

def normalize(text: str) -> str:
    """Без учёта регистра, пунктуации и лишних пробелов: 'hoa lo,' == 'HOA LO'."""
    text = re.sub(r"[^\w\s]", " ", text, flags=re.UNICODE)
    return re.sub(r"\s+", " ", text).strip().casefold()


def verify(answer: str) -> bool:
    return normalize(answer) in {normalize(a) for a in ACCEPTED}


def automate() -> None:
    """Последний шаг цепочки: координаты комплекса из Википедии."""
    params = urllib.parse.urlencode(
        {"action": "query", "prop": "coordinates", "format": "json", "titles": WIKI_TITLE}
    )
    req = urllib.request.Request(
        f"https://en.wikipedia.org/w/api.php?{params}", headers={"User-Agent": "innoctf-osint/1.0"}
    )
    data = json.load(urllib.request.urlopen(req, timeout=20))
    pages = data["query"]["pages"]
    coords = next(iter(pages.values())).get("coordinates")
    if not coords:
        raise SystemExit("[-] Википедия не отдала координаты — проверьте вручную")
    point = coords[0]
    print(f"[+] {WIKI_TITLE}: {point['lat']} N, {point['lon']} E (1 Hoa Lo, Hoan Kiem, Hanoi)")
    print("[+] Ответ:", ANSWER)
    print("[+] Флаг:", FLAG)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--answer", help="ваш ответ: название комплекса")
    args = parser.parse_args()
    if args.answer:
        if verify(args.answer):
            print("[+] Верно. Флаг:", FLAG)
            return 0
        print(f"[-] Не сходится. Ожидалось: {ANSWER}", file=sys.stderr)
        return 1
    automate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
