#!/usr/bin/env python3
"""Поиск CASE_SEAL_KEY в выгрузках Volatility и расшифровка записки."""
import hashlib
import io
import json
import sys
import urllib.request
import zipfile


def xor(data, key, nonce):
    out = bytearray()
    c = 0
    while len(out) < len(data):
        out.extend(hashlib.sha256(key + nonce + c.to_bytes(4, "big")).digest())
        c += 1
    return bytes(a ^ b for a, b in zip(data, out))


def load_zip(target):
    """target — URL живого инстанса (…/download/students.zip или корень) либо путь к zip."""
    if target.startswith("http://") or target.startswith("https://"):
        url = target if target.endswith("students.zip") else target.rstrip("/") + "/download/students.zip"
        return zipfile.ZipFile(io.BytesIO(urllib.request.urlopen(url).read()))
    return zipfile.ZipFile(open(target, "rb"))


archive = load_zip(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13413")
envars = archive.read("volatility/windows.envars.txt").decode()
key = bytes.fromhex(envars.split("CASE_SEAL_KEY=", 1)[1].splitlines()[0])
envelope = json.loads(archive.read("sealed-note.json"))
print(xor(bytes.fromhex(envelope["ciphertext"]), key, bytes.fromhex(envelope["nonce"])).decode())
