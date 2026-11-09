#!/usr/bin/env python3
"""Решатель «Этюд в тонкинских тонах» (osint/easy).

Чистый OSINT: инстанса нет, задача решается внешними источниками. Скрипт
делает два режима:

  python3 solve.py --answer 'Trachypithecus poliocephalus'  # сверить свой ответ
  python3 solve.py                                          # последний шаг автоматом (нужен интернет:
                                                            # профиль вида на eprc.asia)
"""

import argparse
import re
import sys
import urllib.request

ANSWER = "Trachypithecus poliocephalus"
FLAG = "CTF{Trachypithecus poliocephalus}"
SPECIES_PAGE = "https://www.eprc.asia/cat-ba-langur/"


ACCEPTED = ("Trachypithecus poliocephalus", "Trachypithecus poliocephalus poliocephalus")  # канон и подвидовая форма

def normalize(text: str) -> str:
    """Без учёта регистра, пунктуации и лишних пробелов: 'hoa lo,' == 'HOA LO'."""
    text = re.sub(r"[^\w\s]", " ", text, flags=re.UNICODE)
    return re.sub(r"\s+", " ", text).strip().casefold()


def verify(answer: str) -> bool:
    return normalize(answer) in {normalize(a) for a in ACCEPTED}


def automate() -> None:
    """Последний шаг цепочки: подтверждаем латинское название по профилю вида."""
    req = urllib.request.Request(SPECIES_PAGE, headers={"User-Agent": "innoctf-osint/1.0"})
    page = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace")
    hits = sorted(set(re.findall(r"(?i)trachypithecus\s+poliocephalus", page)))
    if not hits:
        raise SystemExit(f"[-] на {SPECIES_PAGE} название вида не найдено — проверьте вручную")
    print(f"[+] {SPECIES_PAGE}: {', '.join(hits)}")
    print("[+] Ответ:", ANSWER)
    print("[+] Флаг:", FLAG)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--answer", help="ваш ответ: латинское название вида")
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
