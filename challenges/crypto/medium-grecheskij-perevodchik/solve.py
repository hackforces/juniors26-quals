#!/usr/bin/env python3
"""Разделение общего простого множителя между RSA-модулями реестра."""
# Идея решения:
# 1. Забираем registry.json: список RSA-«печатей» (n, e) ведомств и записка,
#    зашифрованная флагом; целевой модуль помечен полем target.
# 2. Бракованная печать делит простой множитель с другой печатью реестра:
#    gcd(n_target, n_i) > 1 ровно для одного сертификата — это готовая
#    факторизация n = p*q, 320-битные модули взламывать не нужно.
# 3. phi = (p-1)(q-1), приватная экспонента d = e^(-1) mod phi.
# 4. Разворачиваем RSA-OAEP-подобную обёртку сессионного ключа:
#    key = wrapped^d mod n (16 байт).
# 5. Гамма потока описана в самом JSON: SHA-256(key || nonce || counter_be_32),
#    XOR с шифртекстом — получаем флаг.
import hashlib
import json
import math
import sys
import urllib.request


def xor_stream(data, key, nonce):
    # Поточный шифр из артефакта: гамма = конкатенация SHA-256(key || nonce ||
    # counter_be_32); длина гаммы наращивается блоками по 32 байта, лишний хвост
    # обрезает zip(). Симметричный XOR — той же функцией можно и расшифровать.
    output, counter = bytearray(), 0
    while len(output) < len(data):
        output.extend(hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(a ^ b for a, b in zip(data, output))


def load_registry(target):
    """target — URL живого инстанса (…/download/registry.json или корень) либо путь к файлу."""
    if target.startswith("http://") or target.startswith("https://"):
        url = target if target.endswith("registry.json") else target.rstrip("/") + "/download/registry.json"
        return json.load(urllib.request.urlopen(url))
    return json.load(open(target))


data = load_registry(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13412")
target = next(item for item in data["certificates"] if item["id"] == data["target"])
n = int(target["n"])
# Ключевой трюк: перебираем сертификаты реестра, пока gcd(n_target, n_i) не
# окажется > 1 — этот НОД и есть общий простой множитель p бракованной печати.
factor = next(math.gcd(n, int(item["n"])) for item in data["certificates"] if item is not target and math.gcd(n, int(item["n"])) != 1)
# Факторизация получена бесплатно: q = n // p, дальше стандартный RSA-распад.
phi = (factor - 1) * (n // factor - 1)
private = pow(data["public_exponent"], -1, phi)
key = pow(int(data["wrapped_session_key"]), private, n).to_bytes(16, "big")
plain = xor_stream(bytes.fromhex(data["ciphertext"]), key, bytes.fromhex(data["nonce"]))
print(plain.decode())
