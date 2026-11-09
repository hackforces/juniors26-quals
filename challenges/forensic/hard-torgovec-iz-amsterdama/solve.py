#!/usr/bin/env python3
"""Корреляция pslist/malfind -> sysmon GUID -> ключ, сборка IR-шардов из PCAP, дешифровка."""
# Идея решения:
# 1. Забрать tar.gz выгрузок (тексты Volatility, sysmon.jsonl, PCAP + nonce).
# 2. Из выгрузки malfind — идентификатор сессии и ProcessGuid целевого
#    процесса; сам ключ сессии в памяти не лежит, только зацепка.
# 3. В sysmon.jsonl найти запись EventID 1 с тем же GUID и взять --session-key
#    из CommandLine; у процессов-приманок GUID другие — без корреляции мимо.
# 4. Собрать из PCAP фреймы IR/<session>/<seq>/<slot>/<shard>: слоты 0,1,2 —
#    данные по 3 байта, слот P — XOR-чётность группы.
# 5. В каждой группе не хватает одного слота (номер = seq % 3) — восстановить
#    его как P XOR present0 XOR present1.
# 6. Склеить слоты 0,1,2 по возрастанию seq, срезать нулевой паддинг.
# 7. Расшифровать XOR-гаммой SHA-256(key || nonce || counter_be_32) — флаг.
import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.request


def xor(data, key, nonce):
    # Гаммирование: keystream = SHA-256(key || nonce || counter_be_32),
    # счётчик big-endian; конструкция задокументирована в выгрузке malfind.
    out = bytearray()
    c = 0
    while len(out) < len(data):
        out.extend(hashlib.sha256(key + nonce + c.to_bytes(4, "big")).digest())
        c += 1
    return bytes(a ^ b for a, b in zip(data, out))


def load_tar(target):
    """target — URL живого инстанса (…/download/amsterdam.tar.gz или корень) либо путь к архиву."""
    if target.startswith("http://") or target.startswith("https://"):
        url = target if target.endswith("amsterdam.tar.gz") else target.rstrip("/") + "/download/amsterdam.tar.gz"
        return tarfile.open(fileobj=io.BytesIO(urllib.request.urlopen(url).read()), mode="r:gz")
    return tarfile.open(target, "r:gz")


archive = load_tar(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13414")

# 1. malfind: идентификатор сессии, конструкция потока и ProcessGuid целевого процесса
memory = archive.extractfile("volatility/windows.malfind.txt").read().decode()
session = re.search(r"SESSION=(\w+)", memory).group(1)
guid = re.search(r"ProcessGuid: (\{[0-9A-Fa-f-]+\})", memory).group(1)

# 2. sysmon: ключ — в CommandLine записи EventID 1 с тем же GUID
events = [json.loads(line) for line in archive.extractfile("logs/sysmon.jsonl").read().decode().splitlines() if line.strip()]
matched = [e for e in events if e.get("EventID") == 1 and e.get("ProcessGuid") == guid]
# GUID уникален: событие создания процесса (EventID 1) ровно одно
assert len(matched) == 1
key = bytes.fromhex(re.search(r"--session-key ([0-9a-f]+)", matched[0]["CommandLine"]).group(1))

# 3. PCAP: фреймы IR/<session>/<seq>/<slot>/<shard>, слот P — XOR-чётность
packets = archive.extractfile("network/amsterdam.pcap").read()
nonce = bytes.fromhex(archive.extractfile("network/nonce.txt").read().decode().strip())
# группы regex: 1 — session (фильтр), 2 — seq, 3 — слот (0/1/2/P),
# 4 — 6 hex-символов = 3 байта шарда
groups = {}
for m in re.finditer(rb"IR/([0-9a-f]+)/([0-9]{3})/([012P])/([0-9a-f]{6})", packets):
    assert m.group(1).decode() == session
    groups.setdefault(int(m.group(2)), {})[m.group(3).decode()] = bytes.fromhex(m.group(4).decode())

# 4. восстанавливаем отсутствующий шард чётностью, собираем слоты 0,1,2
data = bytearray()
for seq, group in sorted(groups.items()):
    # номер потерянного слота детерминирован — seq % 3
    missing = str(seq % 3)
    present = [group[str(i)] for i in range(3) if str(i) != missing]
    group[missing] = bytes(a ^ b ^ c for a, b, c in zip(group["P"], present[0], present[1]))
    data.extend(group["0"] + group["1"] + group["2"])

# rstrip: последний кадр выровнен нулевым паддингом до размера слота
print(xor(bytes(data).rstrip(b"\0"), key, nonce).decode())
