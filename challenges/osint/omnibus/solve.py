#!/usr/bin/env python3
"""Решатель «Восточный экспресс… омнибус» (osint/hard).

Чистый OSINT: инстанса нет, задача решается внешними источниками. Скрипт
делает два режима:

  python3 solve.py --answer 'Cat Ba New City Hotel'  # сверить свой ответ
  python3 solve.py                                   # последний шаг автоматом (нужен интернет:
                                                     # поиск отеля в OpenStreetMap/Nominatim)
"""

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request

ANSWER = "Cat Ba New City Hotel"
FLAG = "CTF{Cat Ba New City Hotel}"


ACCEPTED = ("Cat Ba New City Hotel", "Catba New City Hotel")  # канон и слитное написание

def normalize(text: str) -> str:
    """Без учёта регистра, пунктуации и лишних пробелов: 'hoa lo,' == 'HOA LO'."""
    text = re.sub(r"[^\w\s]", " ", text, flags=re.UNICODE)
    return re.sub(r"\s+", " ", text).strip().casefold()


def verify(answer: str) -> bool:
    return normalize(answer) in {normalize(a) for a in ACCEPTED}


def automate() -> None:
    """Последний шаг цепочки: подтверждаем отель по геокодерам (строгий фильтр)."""
    for base in ("https://nominatim.openstreetmap.org/search?", "https://photon.komoot.io/api/?"):
        params = urllib.parse.urlencode({"q": ANSWER, "limit": 5})
        req = urllib.request.Request(base + params, headers={"User-Agent": "innoctf-osint/1.0"})
        try:
            data = json.load(urllib.request.urlopen(req, timeout=20))
        except (OSError, ValueError) as error:
            print(f"[-] {base}: {error}", file=sys.stderr)
            continue
        names = (
            [hit.get("display_name", "") for hit in data]
            if "nominatim" in base
            else [f.get("properties", {}).get("name", "") for f in data.get("features", [])]
        )
        for name in names:
            if normalize(name) == normalize(ANSWER):
                print(f"[+] Найдено: {name}")
                print("[+] Ответ:", ANSWER)
                print("[+] Флаг:", FLAG)
                return
    raise SystemExit(
        "[-] Геокодеры не знают этот отель (малоизвестный POI) — ответ подтверждается "
        "по картам/букинг-агрегаторам вручную"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--answer", help="ваш ответ: название отеля")
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
