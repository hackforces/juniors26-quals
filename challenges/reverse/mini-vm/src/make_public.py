#!/usr/bin/env python3
"""
Build public/mini-vm-files.zip for participants: the oracle binary + a short note.

Asserts the binary leaks no flag/format hints (defence against unintended
`strings`/grep solves). The flag lives only in the server environment, so the
handout cannot contain it.

Usage: python3 src/make_public.py        (uses ./minivm)
       CHAL_BIN=/path/to/minivm python3 src/make_public.py
"""

import os
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(os.environ.get("CHAL_BIN", ROOT / "minivm"))
OUT = ROOT / "public" / "mini-vm-files.zip"

NOTE = (
    "mini-vm\n"
    "=======\n\n"
    "minivm - статический ELF x86-64. Это оракул функции P над 16-байтным\n"
    "блоком: на вход 32 hex-символа, на выход 32 hex-символа P(блока).\n\n"
    "  $ ./minivm 00112233445566778899aabbccddeeff\n"
    "  (печатает P(block) в hex)\n\n"
    "Сервис выдаёт случайный y и просит прислать x, такой что P(x) = y,\n"
    "за ограниченное время. Разберите P, постройте обратную функцию и\n"
    "подключайтесь:  nc <ip> 1338\n"
)


def main() -> None:
    data = BIN.read_bytes()
    low = data.lower()
    for bad in (b"ctf{", b"innoctf{", b"flag{", b"access granted", b"the flag"):
        if bad in low:
            sys.exit(f"[!] refuse to ship: {bad!r} present in {BIN}")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(BIN, "minivm")
        z.writestr("README.txt", NOTE)
    print(f"[+] wrote {OUT} ({OUT.stat().st_size} bytes); no flag/format leak")


if __name__ == "__main__":
    main()
