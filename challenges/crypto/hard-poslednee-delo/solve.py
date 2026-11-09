#!/usr/bin/env python3
"""Восстановление приватного ключа secp256k1 по ECDSA-захватам с общим хвостом nonce."""
# Идея решения:
# 1. Забираем telemetry.json: 7 подписей secp256k1 (r, s, хэш z, старшая часть
#    nonce h) и зашифрованное флагом сообщение; ключ потока = SHA-256(d_be_32).
# 2. У неисправного подписчика младшие 32 бита nonce («счётный регистр»)
#    одинаковы: k_i = h_i*2^32 + tail. tail неизвестен, h_i сообщает телеметрия.
# 3. Каждая подпись даёт линейное уравнение s*k = z + r*d (mod N) с двумя
#    неизвестными (tail, d). Берём две подписи и исключаем d: подстановка
#    k_i = h_i*2^32 + tail даёт a_i = s_i*h_i*2^32 - z_i = r_i*d - s_i*tail.
# 4. Из пары уравнений — одно линейное сравнение на tail:
#    tail = (r1*a2 - r2*a1) * (r2*s1 - r1*s2)^(-1) mod N.
# 5. Подставляем tail в k1 и выражаем приватный ключ d = (s1*k1 - z1)/r1 mod N;
#    остальные захваты независимо подтверждают d.
# 6. key = SHA-256(d_be_32), гамма SHA-256(key || nonce || counter_be_32), XOR.
import hashlib
import json
import sys
import urllib.request

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# ^ порядок группы secp256k1: все уравнения подписи живут в Z_N, поэтому
# деление по модулю N (pow(..., -1, N)) легально и обратные всегда существуют.


def stream_xor(data, key, nonce):
    # Гамма = SHA-256(key || nonce || counter_be_32), блоками по 32 байта;
    # формат задокументирован в самом артефакте телеметрии.
    output, counter = bytearray(), 0
    while len(output) < len(data):
        output.extend(hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(a ^ b for a, b in zip(data, output))


def load_telemetry(target):
    """target — URL живого инстанса (…/download/telemetry.json или корень) либо путь к файлу."""
    if target.startswith("http://") or target.startswith("https://"):
        url = target if target.endswith("telemetry.json") else target.rstrip("/") + "/download/telemetry.json"
        return json.load(urllib.request.urlopen(url))
    return json.load(open(target))


data = load_telemetry(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13411")
# Двух захватов достаточно: два уравнения — две неизвестные (tail, d).
first, second = data["captures"][:2]
base = 1 << 32
r1, s1, z1, h1 = (int(first[key]) for key in ("r", "s", "z", "nonce_high"))
r2, s2, z2, h2 = (int(second[key]) for key in ("r", "s", "z", "nonce_high"))
# k_i = h_i*2^32 + tail, поэтому s_i*k_i - z_i = s_i*(h_i*2^32) - z_i + s_i*tail;
# a_i — известная часть уравнения r_i*d = a_i + s_i*tail (mod N).
a1 = (s1 * h1 * base - z1) % N
a2 = (s2 * h2 * base - z2) % N
# Исключаем d: r1*(a2 + s2*tail) = r2*(a1 + s1*tail) => линейное сравнение
# (r2*s1 - r1*s2)*tail = r1*a2 - r2*a1; обращаем коэффициент по модулю N.
tail = (r1 * a2 - r2 * a1) * pow(r2 * s1 - r1 * s2, -1, N) % N
# Теперь k1 известен полностью — приватный ключ прямо из уравнения подписи.
private = (s1 * (h1 * base + tail) - z1) * pow(r1, -1, N) % N
key = hashlib.sha256(private.to_bytes(32, "big")).digest()
payload = data["message_cipher"]
print(stream_xor(bytes.fromhex(payload["ciphertext"]), key, bytes.fromhex(payload["nonce"])).decode())
