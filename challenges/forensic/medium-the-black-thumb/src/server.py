"""«Чёрный палец» — runtime: ZIP из живого флага + patch образа + раздача.

Последовательность (build при import, до HTTP — паттерн ubijstvo):
  1) flag = env CTF_FLAG (RuntimeError если пусто);
  2) читаем base-образ (256 MiB, Task 1), assert sealed-область == 0×4096;
  3) tmpdir: letter.txt (статичный нарратив) + flag.txt (= CTF_FLAG + \n);
     zip -q -P <CODE> -j (info-zip, ZipCrypto — читается Windows unzip/7-Zip
     и python zipfile(pwd=));
  4) assert len(zip) <= 4096 (размер sealed.bin, иначе образ сломан);
  5) self-check: zipfile(pwd=CODE) читает flag.txt; без pwd — BadZipFile;
  6) patch-копия образа: out[off:off+len(zip)] = zip (остальные блоки нули);
  7) gzip → /srv/public/download/black-thumb.img.gz
     (compresslevel=1: в образе ~100 МБ несжимаемого декор-медиа, level 9
     гонял бы старт минуту+ и попадал в таймаут healthcheck; на нулях
     пустого ext4 уровень почти не влияет на размер);
  8) HTTP 8080: /health (200 после сборки) + раздача хэндаута по контракту
     (GET / → файл с Content-Disposition).

Итого: /health поднимается только после успешного patch; время = шаги 2–7.
"""

import gzip
import io
import json
import os
import subprocess
import tempfile
import zipfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# та же константа, что в build_image.py (контент, не секрет)
CODE = "black-thumb-2050"

LETTER_TXT = """\
Второй отсек.

Кто ты, что ты заходишь сюда? Я оставил здесь то, что не хочу
носить с собой. Второй отсек этого носителя — не для гостей.

Код на ключе ты уже знаешь: он же подпись, которая стоит
на каждом твоём донесе, если ты читал их по порядку.

Флаг — в flag.txt, рядом с этим письмом. Пакет заперт тем
же кодом. Это и есть вся защита: не механизм, а то, что
никто не догадается, что здесь вообще что-то есть.

Кран, К.
2050.
"""

flag = os.environ.get("CTF_FLAG", "")
if not flag:
    raise RuntimeError("CTF_FLAG must be set")

# 1) base-образ + manifest (Task 1)
with open("/srv/base/manifest.json") as f:
    manifest = json.load(f)
off = manifest["sealed_bin_offset"]
sealed_size = manifest["sealed_bin_size"]
base = open("/srv/base/black-thumb-base.img", "rb").read()
assert off + sealed_size <= len(base), "manifest out of range"
if base[off:off + sealed_size] != b"\x00" * sealed_size:
    raise RuntimeError("sealed.bin in base image is not zeroed (stale build?)")

# 2) ZIP (ZipCrypto, info-zip) в tmpdir
with tempfile.TemporaryDirectory() as td:
    zip_path = os.path.join(td, "sealed.zip")
    letter_path = os.path.join(td, "letter.txt")
    flag_path = os.path.join(td, "flag.txt")
    with open(letter_path, "w", encoding="utf-8") as f:
        f.write(LETTER_TXT)
    with open(flag_path, "w", encoding="utf-8") as f:
        f.write(flag + "\n")
    # absolute paths: cwd контейнера — / (WORKDIR не задан),
    # а tempdir — /tmp/tmpXXXX
    subprocess.run(
        ["zip", "-q", "-P", CODE, "-j", zip_path, letter_path, flag_path],
        check=True,
    )
    zip_bytes = open(zip_path, "rb").read()

    # 3) self-check: читается с кодом, не читается без
    if len(zip_bytes) > sealed_size:
        raise RuntimeError(
            "zip %d B > sealed.bin %d B" % (len(zip_bytes), sealed_size)
        )
    # (pwd не аргумент ZipFile.__init__ — только setpassword()/open())
    z = zipfile.ZipFile(io.BytesIO(zip_bytes))
    z.setpassword(CODE.encode())
    assert z.read("flag.txt") == flag.encode() + b"\n", "self-check: flag.txt"
    try:
        zipfile.ZipFile(io.BytesIO(zip_bytes)).read("flag.txt")
    except (zipfile.BadZipFile, RuntimeError):
        pass  # как и должно: ZipCrypto без пароля
    else:
        raise RuntimeError("self-check: zip reads without password")

# 4) patch + gzip (compresslevel=1 — см. docstring: старт ≤ healthcheck)
out = bytearray(base)
out[off:off + len(zip_bytes)] = zip_bytes
os.makedirs("/srv/public/download", exist_ok=True)
with gzip.open("/srv/public/download/black-thumb.img.gz", "wb", compresslevel=1) as f:
    f.write(bytes(out))

# 5) HTTP (health доступен только после успешной сборки)


# Единый контракт выдачи хэндаута: GET / отдаёт файл напрямую
# (Content-Disposition: attachment); /<file> и /download/<file> — алиасы,
# остальное — 404 (листинга папки нет).
NAME = "black-thumb.img.gz"
FILE = Path("/srv/public/download") / NAME


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if path not in ("/", "/" + NAME, "/download/" + NAME):
            self.send_error(404)
            return
        data = FILE.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", f'attachment; filename="{NAME}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
