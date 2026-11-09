#!/usr/bin/env python3
"""Мобильная форензика: notification -> conversations db -> uuid -> MOBILE-запись в PCAP."""
# Идея решения:
# 1. Забрать zip-бэкап (URL инстанса или путь к файлу) и распаковать: внутри
#    SQLite-БД мессенджера, shared_prefs, settings_secure, bugreport и PCAP.
# 2. Уведомление из bugreport/notifications.txt называет целевой диалог abbey-N —
#    без него в БД три неразличимых диалога-приманки.
# 3. Из messages.db достаём attachment_uuid именно этого диалога.
# 4. Ключ = SHA-256(upload_seed || android_id): seed — base64 в текстовом узле
#    shared_prefs/device.xml, android_id — из settings_secure.xml (рецепт — app-log).
# 5. В PCAP найти запись MOBILE/<uuid>/<nonce>/<ciphertext> с тем же uuid —
#    декойные записи с чужими uuid (и просто «первая попавшаяся») не подходят.
# 6. Расшифровать ciphertext XOR-гаммой SHA-256(key || nonce || counter_be_32) — флаг.
import base64
import hashlib
import io
import re
import sqlite3
import sys
import tempfile
import urllib.request
import zipfile


def xor(data, key, nonce):
    # Гаммирование документированным в app-log.txt потоком:
    # keystream = SHA-256(key || nonce || counter_be_32), счётчик big-endian.
    out = bytearray()
    c = 0
    while len(out) < len(data):
        out.extend(hashlib.sha256(key + nonce + c.to_bytes(4, "big")).digest())
        c += 1
    return bytes(a ^ b for a, b in zip(data, out))


def load_zip(target):
    """target — URL живого инстанса (…/download/abbey.zip или корень) либо путь к zip."""
    if target.startswith("http://") or target.startswith("https://"):
        url = target if target.endswith("abbey.zip") else target.rstrip("/") + "/download/abbey.zip"
        return zipfile.ZipFile(io.BytesIO(urllib.request.urlopen(url).read()))
    return zipfile.ZipFile(open(target, "rb"))


archive = load_zip(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13415")
with tempfile.TemporaryDirectory() as directory:
    archive.extractall(directory)
    # 1. уведомление указывает целевой диалог
    conversation = re.search(r"conversation=(abbey-\d+)", archive.read("bugreport/notifications.txt").decode()).group(1)
    # 2. uuid вложения — из строки этого диалога в SQLite
    db = sqlite3.connect(f"{directory}/data/data/org.newbaker.courier/databases/messages.db")
    uuid = db.execute('select attachment_uuid from messages where conversation=?', (conversation,)).fetchone()[0]
    db.close()
    # 3. ключ по рецепту из app-log.txt: SHA-256(upload_seed || android_id)
    # upload_seed хранится base64-строкой в текстовом узле device.xml
    seed = base64.b64decode(re.search(r">([^<]+)<", archive.read("data/data/org.newbaker.courier/shared_prefs/device.xml").decode()).group(1))
    android_id = re.search(r'value="([0-9a-f]+)"', archive.read("data/system/users/0/settings_secure.xml").decode()).group(1)
    key = hashlib.sha256(seed + android_id.encode()).digest()

# 4. корреляция по uuid: MOBILE/<uuid>/<nonce>/<ciphertext> в PCAP (приманки отбрасываются)
packet = archive.read("network/night-upload.pcap")
# группы regex: 1 — uuid (фильтр), 2 — nonce, 3 — ciphertext
found = [m for m in re.finditer(rb"MOBILE/([0-9a-f]+)/([0-9a-f]+)/([0-9a-f]+)", packet) if m.group(1).decode() == uuid][0]
print(xor(bytes.fromhex(found.group(3).decode()), key, bytes.fromhex(found.group(2).decode())).decode())
