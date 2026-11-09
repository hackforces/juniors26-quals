#!/usr/bin/env python3
"""LSB синего канала PPM -> поток байтов до NUL."""
import sys
import urllib.request


def load_ppm(target):
    """target — URL живого инстанса (…/download/portrait.ppm или корень) либо путь к файлу."""
    if target.startswith("http://") or target.startswith("https://"):
        url = target if target.endswith("portrait.ppm") else target.rstrip("/") + "/download/portrait.ppm"
        return urllib.request.urlopen(url).read()
    return open(target, "rb").read()


data = load_ppm(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13431")
d = data.split(b"\n", 3)[3]  # заголовок P6/W/H/maxval отброшен — дальше пиксели RGB
bits = "".join(str(x & 1) for x in d[2::3])  # младший бит синего канала
out = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
print(out.split(b"\0")[0].decode())
