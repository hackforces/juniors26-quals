#!/usr/bin/env python3
"""Решатель «Чайное происшествие» (osint/hard).

Чистый OSINT (хард-версия без метаданных): инстанса нет, задача решается
внешними источниками. Скрипт делает два режима:

  python3 solve.py --answer 'YaKorea Hostel Gangnam'  # сверить свой ответ
  python3 solve.py                                    # последний шаг автоматом (нужен интернет:
                                                      # поиск хостела в OpenStreetMap/Nominatim)
"""

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request

ANSWER = "YaKorea Hostel Gangnam"
FLAG = "CTF{YaKorea Hostel Gangnam}"


ACCEPTED = ("YaKorea Hostel Gangnam", "YaKorea Hostel Gangnam, Seoul")  # канон и форма с городом

def normalize(text: str) -> str:
    """Без учёта регистра, пунктуации и лишних пробелов: 'hoa lo,' == 'HOA LO'."""
    text = re.sub(r"[^\w\s]", " ", text, flags=re.UNICODE)
    return re.sub(r"\s+", " ", text).strip().casefold()


def verify(answer: str) -> bool:
    return normalize(answer) in {normalize(a) for a in ACCEPTED}


def automate() -> None:
    """Последний шаг цепочки: подтверждаем хостел по геокодеру (Photon/Komoot)."""
    params = urllib.parse.urlencode({"q": "YaKorea Hostel Gangnam Seoul", "limit": 5, "lang": "en"})
    req = urllib.request.Request(
        f"https://photon.komoot.io/api/?{params}", headers={"User-Agent": "innoctf-osint/1.0"}
    )
    data = json.load(urllib.request.urlopen(req, timeout=20))
    for feature in data.get("features", []):
        props = feature.get("properties", {})
        name = props.get("name", "")
        if "yakorea" in normalize(name).replace(" ", "") or normalize(name) in {
            normalize(a) for a in ACCEPTED
        }:
            lon, lat = feature["geometry"]["coordinates"]
            print(f"[+] Найдено: {name} ({props.get('city')}, {props.get('country')}) — {lat}, {lon}")
            print("[+] Ответ:", ANSWER)
            print("[+] Флаг:", FLAG)
            return
    raise SystemExit(
        "[-] Геокодер не знает хостел — сайт сети недоступен, поднимите его в "
        "web.archive.org или проверьте ответ по картам вручную"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--answer", help="ваш ответ: название заведения")
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
