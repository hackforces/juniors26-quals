#!/usr/bin/env python3
"""«Чёрный палец» — скачивание декор-медиа для образа флешки.

Запускается на docker build ДО build_image.py (в CI сеть есть; слой
кэшируется, повторный запуск идемпотентен). Только stdlib.

Каждый файл проверяется по magic bytes и минимальному размеру;
одиночный сбой — skip с warning (медиа — чистый декор и не должен
ломать ядро задачи), но если в категории живых осталось меньше MIN_OK —
выход с ошибкой, чтобы мёртвые URL заметили и заменили.

Источники — публичные тестовые ассеты и общественное достояние,
доступные из CI (часть классических хостингов типа picsum/googleapis
отдаёт 403 из этого региона — проверено 2026-10-25, поэтому их нет):
  photos  Wikimedia Commons, классические картины (Special:FilePath,
          thumb ?width=1280; между запросами пауза — там rate-limit)
  music   SoundHelix Songs 1-10 (канонические sample-mp3)
  video   10s клипы Big Buck Bunny / Sintel / Jellyfish
          (test-videos.co.uk)

Раскладку по томам (первая половина списка → P1, вторая → скрытый том)
определяет build_image.py --media-dir.

Usage: python3 download_media.py /srv/media-src
"""

from __future__ import annotations

import sys
import time
import urllib.request
from pathlib import Path

MIN_OK = 7  # живых файлов в категории, ниже — падение сборки

WM = "https://commons.wikimedia.org/wiki/Special:FilePath"
TV = "https://test-videos.co.uk/vids"
SH = "https://www.soundhelix.com/examples/mp3"

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) innoctf-handout-builder"}

PAUSE = 2.0  # пауза между файлами (Wikimedia thumb-render режет 429 за бурст)


def is_jpg(head: bytes) -> bool:
    return head[:3] == b"\xff\xd8\xff"


def is_mp3(head: bytes) -> bool:
    # ID3v2-заголовок либо frame sync 0xFFEx
    return head[:3] == b"ID3" or (head[:1] == b"\xff" and (head[1] & 0xE0) == 0xE0)


def is_mp4(head: bytes) -> bool:
    return head[4:8] == b"ftyp"


def is_png(head: bytes) -> bool:
    return head[:4] == b"\x89PNG"


WM_PAINTINGS = [  # (имя на флешке, имя файла на Commons)
    ("starry-night.jpg", "Van_Gogh_-_Starry_Night_-_Google_Art_Project.jpg"),
    ("mona-lisa.jpg", "Mona_Lisa%2C_by_Leonardo_da_Vinci%2C_from_C2RMF_retouched.jpg"),
    ("great-wave.jpg", "The_Great_Wave_off_Kanagawa.jpg"),
    ("american-gothic.jpg", "Grant_Wood_-_American_Gothic_-_Google_Art_Project.jpg"),
    ("the-scream.jpg", "The_Scream.jpg"),
    ("wanderer-above-the-fog.jpg", "Caspar_David_Friedrich_-_Wanderer_above_the_sea_of_fog.jpg"),
    ("cafe-terrace-at-night.jpg", "Vincent_Willem_van_Gogh_128.jpg"),
    ("garden-of-earthly-delights.jpg", "The_Garden_of_Earthly_Delights_by_Bosch_High_Resolution.jpg"),
    ("monk-by-the-sea.jpg", "Caspar_David_Friedrich_-_Der_M%C3%B6nch_am_Meer_-_Google_Art_Project.jpg"),
    ("napoleon-in-his-study.jpg", "Jacques-Louis_David_-_The_Emperor_Napoleon_in_His_Study_at_the_Tuileries_-_Google_Art_Project.jpg"),
]

TV_CLIPS = [  # (имя на флешке, путь на test-videos.co.uk)
    ("Big_Buck_Bunny_360_10s_1MB.mp4", "bigbuckbunny/mp4/h264/360/Big_Buck_Bunny_360_10s_1MB.mp4"),
    ("Big_Buck_Bunny_360_10s_2MB.mp4", "bigbuckbunny/mp4/h264/360/Big_Buck_Bunny_360_10s_2MB.mp4"),
    ("Big_Buck_Bunny_720_10s_1MB.mp4", "bigbuckbunny/mp4/h264/720/Big_Buck_Bunny_720_10s_1MB.mp4"),
    ("Sintel_360_10s_1MB.mp4", "sintel/mp4/h264/360/Sintel_360_10s_1MB.mp4"),
    ("Sintel_360_10s_2MB.mp4", "sintel/mp4/h264/360/Sintel_360_10s_2MB.mp4"),
    ("Sintel_720_10s_1MB.mp4", "sintel/mp4/h264/720/Sintel_720_10s_1MB.mp4"),
    ("Sintel_720_10s_2MB.mp4", "sintel/mp4/h264/720/Sintel_720_10s_2MB.mp4"),
    ("Jellyfish_360_10s_1MB.mp4", "jellyfish/mp4/h264/360/Jellyfish_360_10s_1MB.mp4"),
    ("Jellyfish_720_10s_2MB.mp4", "jellyfish/mp4/h264/720/Jellyfish_720_10s_2MB.mp4"),
    ("Big_Buck_Bunny_1080_10s_1MB.mp4", "bigbuckbunny/mp4/h264/1080/Big_Buck_Bunny_1080_10s_1MB.mp4"),
]

MEDIA: dict[str, list[tuple[str, str, int, object]]] = {
    "photos": [
        (name, f"{WM}/{commons}?width=1280", 30_000, is_jpg)
        for name, commons in WM_PAINTINGS
    ],
    "music": [
        ("SoundHelix-Song-%d.mp3" % i, f"{SH}/SoundHelix-Song-%d.mp3" % i,
         1_000_000, is_mp3)
        for i in range(1, 11)
    ],
    "video": [
        (name, f"{TV}/{path}", 500_000, is_mp4)
        for name, path in TV_CLIPS
    ],
}


def fetch(url: str, dest: Path, timeout: int = 120, attempts: int = 3) -> bool:
    for n in range(attempts):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
                while True:
                    chunk = r.read(1 << 16)
                    if not chunk:
                        break
                    f.write(chunk)
            return True
        except Exception as exc:  # noqa: BLE001 — причины разнообразны, retry
            sys.stderr.write(f"  ! {dest.name}: попытка {n + 1} не удалась: {exc}\n")
            time.sleep(3.0 * (n + 1))  # backoff, Wikimedia отвечает 429 на бурст
    return False


def valid(dest: Path, min_size: int, check) -> bool:
    try:
        if dest.stat().st_size < min_size:
            return False
        with open(dest, "rb") as f:
            return bool(check(f.read(16)))
    except OSError:
        return False


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    root = Path(sys.argv[1])
    root.mkdir(parents=True, exist_ok=True)
    fail = False
    total = 0
    for cat, items in MEDIA.items():
        d = root / cat
        d.mkdir(exist_ok=True)
        good = 0
        for name, url, min_size, check in items:
            dest = d / name
            if valid(dest, min_size, check):
                good += 1
                total += dest.stat().st_size
                continue
            if fetch(url, dest) and valid(dest, min_size, check):
                good += 1
                total += dest.stat().st_size
                print(f"  + {cat}/{name} ({dest.stat().st_size} B)")
            else:
                dest.unlink(missing_ok=True)
                sys.stderr.write(f"  ! {cat}/{name}: SKIPPED (декор, не влияет на решение)\n")
            time.sleep(PAUSE)
        print(f"{cat}: {good}/{len(items)}")
        if good < MIN_OK:
            fail = True
            sys.stderr.write(f"  !! категория {cat}: {good} < {MIN_OK}, сборка падает\n")
    print(f"итого: {total} байт медиа в {root}")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
