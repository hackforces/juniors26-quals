#!/usr/bin/env python3
# Идея решения:
# 1. Забираем bell.wav с эндпоинта /download живого инстанса (или берём локальный файл).
# 2. Контейнер — моно WAV 8 кГц, 16-битный PCM: сообщение спрятано в младших битах
#    семплов — замена LSB на слух не заметна.
# 3. Читаем все кадры и трактуем байты как little-endian int16.
# 4. Снимаем младший бит каждого семпла, склеиваем биты в байты MSB-first.
# 5. Полезная нагрузка идёт до первого NUL — печатаем её, это и есть флаг.
"""LSB 16-битных PCM-семплов WAV -> поток байтов до NUL."""
import io
import struct
import sys
import urllib.request
import wave


def load_wav(target):
    """target — URL живого инстанса (…/download/bell.wav или корень) либо путь к файлу."""
    if target.startswith("http://") or target.startswith("https://"):
        # корень инстанса автоматически дополняем путём до файла
        url = target if target.endswith("bell.wav") else target.rstrip("/") + "/download/bell.wav"
        return io.BytesIO(urllib.request.urlopen(url).read())
    return open(target, "rb")


# модуль wave разбирает RIFF-заголовок — сразу получаем чистые PCM-кадры
with wave.open(load_wav(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13433"), "rb") as w:
    # сырой PCM: чётное число байт, по 2 байта (int16 LE) на семпл
    d = w.readframes(w.getnframes())

# младший бит каждого int16-семпла -> цепочка битов стеганоконтейнера
bits = "".join(str(x & 1) for x in struct.unpack("<" + "h" * (len(d) // 2), d))
# склейка битов в байты MSB-first: первый бит — старший бит первого байта
o = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
# сообщение терминируется NUL — отрезаем хвост контейнера и печатаем флаг
print(o.split(b"\0")[0].decode())
