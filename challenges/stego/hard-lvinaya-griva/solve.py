#!/usr/bin/env python3
# Идея решения:
# 1. Забираем coast.png с /download (или берём локальный файл): PNG 128×128 RGB;
#    заметка в tEXt-чанке подсказывает схему: «красные волокна отмечают нужные
#    синие, читайте их в порядке развёртки».
# 2. Парсим структуру PNG вручную: IHDR даёт размеры, IDAT — сжатые данные
#    (чанков может быть несколько — склеиваем).
# 3. Распаковываем IDAT через zlib — получаем сырые сканлайны.
# 4. Карта выбора спрятана в красной битовой плоскости: пиксель отмечен, если
#    LSB его красного канала равен 1.
# 5. С отмеченных пикселей снимаем LSB синего канала в порядке развёртки —
#    строки сверху вниз, внутри строки слева направо.
# 6. Биты -> байты MSB-first; собранный поток начинается с zlib-заголовка —
#    распаковываем и получаем флаг.
"""PNG: карта выбора в red-плоскости, LSB синего -> zlib-поток -> флаг."""
import struct
import sys
import urllib.request
import zlib


def load_png(target):
    """target — URL живого инстанса (…/download/coast.png или корень) либо путь к файлу."""
    if target.startswith("http://") or target.startswith("https://"):
        url = target if target.endswith("coast.png") else target.rstrip("/") + "/download/coast.png"
        return urllib.request.urlopen(url).read()
    return open(target, "rb").read()


data = load_png(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13432")

# разбор чанков PNG: размеры из IHDR, данные из IDAT
position = 8
idat = b""
while position < len(data):
    size = struct.unpack("!I", data[position : position + 4])[0]
    kind = data[position + 4 : position + 8]
    value = data[position + 8 : position + 8 + size]
    # чанк = 4 байта длины + 4 типа + данные + 4 CRC
    position += 12 + size
    if kind == b"IHDR":
        width, height = struct.unpack("!II", value[:8])
    if kind == b"IDAT":
        idat += value

# распаковка сканлайнов (фильтр-байт на строку), выбор пикселей по LSB красного
raw = zlib.decompress(idat)
bits = []
position = 0
for _y in range(height):
    # префикс-байт фильтра PNG у каждой строки — пропускаем его
    position += 1
    for _x in range(width):
        red, _green, blue = raw[position : position + 3]
        position += 3
        # отмеченный пиксель (LSB красного = 1): выносим LSB синего в поток
        if red & 1:
            bits.append(str(blue & 1))

# порядок сбора (строка за строкой) и есть порядок развёртки из заметки
stream = "".join(bits)
# биты -> байты MSB-first
payload = bytes(int(stream[i : i + 8], 2) for i in range(0, len(stream) - 7, 8))
# «нить была свёрнута терминалом побережья»: поток — zlib, распаковываем
print(zlib.decompress(payload).decode())
