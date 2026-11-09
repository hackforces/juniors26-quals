#!/usr/bin/env python3
"""Deterministic builder for the 256 MiB «чёрный палец» USB-stick image.

The base image contains NO flag and no flag-derived data: the
``sealed.bin`` area inside the hidden ext2 volume is 4096 zero bytes and
the runtime (``server.py``) patches it with a password-protected zip built
from ``CTF_FLAG``.  The build therefore never reads the flag, and the
Docker layer that stores the base image is flag-independent.

Layout (byte offsets from the start of the image):

  0 .. 511          MBR: one 0x83 partition, LBA 2048..264192
                    (1 MiB .. 129 MiB), 0x55AA signature
  1 .. 129 MiB      P1: ext4, 1 KiB blocks, label ``usbdisk`` — the
                    courier's home: notes, chat, history, docs, media
  129 .. 145 MiB    decoy: repeating 64-byte tile (pure ASCII, no 0x53
                    and no bytes >= 0x80, so no accidental ext magic)
                    with one planted fake ext superblock at +1024:
                    magic 0xEF53, state 0, blocks_count 0,
                    label ``recovery``
  145 .. 256 MiB    hidden ext2 volume, 1 KiB blocks, label
                    ``black-thumb-2050``; the root holds ``note.txt``
                    and ``sealed.bin`` (4096 zero bytes)

Built with mke2fs + debugfs (e2fsprogs) and dd: no loop mounts, no
root.  Prose content is deterministic (seeded with
``random.Random(2050)``); decoy media (photos/music/video, downloaded
beforehand by ``download_media.py`` into ``--media-dir``) is embedded
into P1 (``/home/crane/media/<cat>/``, first half of each category)
and the hidden volume (``/<cat>/``, second half).

Usage:
    python3 build_image.py --out DIR [--media-dir DIR] [--verify]
"""

from __future__ import annotations

import argparse
import json
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

# ----------------------------------------------------------------- constants

IMAGE_SIZE = 268435456          # 256 MiB
P1_OFF = 1048576                # 1 MiB
P1_SIZE = 134217728             # 128 MiB
FAKE_OFF = 135266304            # 129 MiB
FAKE_SIZE = 16777216            # 16 MiB
HIDDEN_OFF = 152043520          # 145 MiB
HIDDEN_SIZE = 116391936         # 111 MiB = 113664 x 1 KiB
BLOCK = 1024

CODE = "black-thumb-2050"       # shared with server.py (content, not a secret)
FAKE_LABEL = "recovery"
HIDDEN_LABEL = "black-thumb-2050"
P1_LABEL = "usbdisk"

IMG_NAME = "black-thumb-base.img"
MANIFEST_NAME = "manifest.json"

# ext superblock field offsets, relative to the volume start (1 KiB blocks:
# the superblock block is 1024..2047).  Verified 2026-10-24 against
# mke2fs 1.47 (Ubuntu 24.04): s_blocks_count +1028, s_magic +1080 (=0x438
# from the volume start), s_state +1082, s_inode_size +1112 (256 in 1.47),
# s_volume_name +1144 (16 bytes).
SB_BLOCKS = 1028
SB_MAGIC = 1080
SB_STATE = 1082
SB_LABEL = 1144
MAGIC = b"\x53\xef"             # 0xEF53, little-endian on disk

SEAL_SIZE = 4096

# Декор-медиа (скачивается download_media.py на docker build; в образ
# пишется через debugfs, как и прозаические файлы).  Раскладка: первые
# MEDIA_SPLIT файлов каждой категории → P1 (/home/crane/media/<cat>/),
# остальные → скрытый том (/<cat>/).
MEDIA_CATEGORIES = ("photos", "music", "video")
MEDIA_SPLIT = 5

# ------------------------------------------------------------------- helpers


def run(cmd: list[str]) -> None:
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode != 0:
        sys.stderr.write(p.stdout.decode("utf-8", "replace"))
        sys.stderr.write(p.stderr.decode("utf-8", "replace"))
        raise RuntimeError(f"command failed (rc={p.returncode}): {' '.join(cmd[:3])}")


def run_out(cmd: list[str]) -> bytes:
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode != 0:
        sys.stderr.write(p.stdout.decode("utf-8", "replace"))
        sys.stderr.write(p.stderr.decode("utf-8", "replace"))
        raise RuntimeError(f"command failed (rc={p.returncode}): {' '.join(cmd[:3])}")
    return p.stdout


# --------------------------------------------------------------------- MBR


def build_mbr() -> bytes:
    mbr = bytearray(512)
    mbr[510:512] = b"\x55\xAA"
    e = 446  # first partition entry
    mbr[e] = 0x00                      # status
    mbr[e + 1:e + 4] = b"\x00\x01\x00"  # CHS start (head 0, sector 1, cyl 0)
    mbr[e + 4] = 0x83                  # type: Linux
    mbr[e + 5:e + 8] = b"\x00\xFF\xFF"  # CHS end
    struct.pack_into("<II", mbr, e + 8, 2048, P1_SIZE // 512)  # lba start/count
    return bytes(mbr)


# ------------------------------------------------------------------ content

README_TXT = """\
Кран, К. — курьер южного хранилища

2026-10-24. Флешку сдал добровольно, без предупреждений.
По таблице разделов на носителе один том, 128 МБ — и это
правда, но это не весь носитель. То, что за таблицей, я
покажу сам, если доживу до разговора с вами.

Читайте notes/ в том порядке, в каком я их писал:
sticky.txt — актуально, old-drive.txt — старое, не действует.
"""

STICKY_TXT = """\
Актуальный код (2050): black-thumb-2050
Записал в двух местах — здесь и в note.txt на самом отсеке.
Первая «сигнатура» в хвосте флешки — мимикрия. Не гнаться.
"""

OLD_DRIVE_TXT = """\
2049, silver case.
Код silver-case-2049.
Кейс закрыт, код сжег. Не действует.
"""

TRANSCRIPT_TXT = """\
[2026-09-30 01:12] dispatcher: слышал, ты что-то прячешь в хвосте флешки
[2026-09-30 01:14] crane: второй отсек? ты про какой второй отсек
[2026-09-30 01:15] dispatcher: не важно. если проверят — скажешь, что там один том
[2026-09-30 01:16] crane: по таблице — да. остальное не в таблице
[2026-09-30 01:17] dispatcher: и кто-то реально по хвосту поедет?
[2026-09-30 01:18] crane: а вдруг. поэтому и поставил ложную сигнатуру в начало хвоста
[2026-09-30 01:19] dispatcher: recovery partition, пусть играют
[2026-09-30 01:20] crane: пусть.
"""

BASH_HISTORY = """\
mke2fs -t ext2 -b 1024 -L black-thumb-2050 /tmp/hidden.img
dd if=/tmp/hidden.img of=/dev/sdb bs=1M seek=145
rm -f /tmp/hidden.img
dd if=/tmp/pattern.bin of=/dev/sdb bs=4096 seek=129 count=4096
rm -f /tmp/pattern.bin
blkid /dev/sdb
"""

HISTORY_CSV = """\
2026-09-26 22:40,https://arhiv.2050/courier/manifests/2026-09
2026-09-26 22:51,https://streets.2050/south-warehouse/clocks
2026-09-27 01:03,https://arhiv.2050/ledger/inks
2026-09-27 01:47,https://docks.2050/lanterns/route-7
2026-09-28 00:15,https://arhiv.2050/courier/stamps/2049
2026-09-28 02:31,https://streets.2050/south-warehouse/fog
2026-09-28 03:02,https://docks.2050/crates/pallet-11
2026-09-29 01:22,https://arhiv.2050/ledger/seals
2026-09-29 02:10,https://arhiv.2050/courier/manifests/2026-10
2026-09-30 01:21,https://streets.2050/south-warehouse/notes
"""

NOTE_TXT = """\
Кран, К. — записка

Вы нашли отсек, которого нет в таблице. Это нормально:
таблица говорит, что на носителе один том, и в этом она
не врёт — она просто не говорит про второй.

Внутри два файла. Этот — вам, и он открыт. Второй —
sealed.bin — я запечатал, потому что в нём то, что
не для диспетчера и не для архива.

Код к файлу sealed.bin: black-thumb-2050

Не пересылайте его дальше. Южное хранилище, 2050.
Если спросите, кто я, — скажите, что курьер уже уволился.
"""

DOC_WORDS = """\
южное хранилище лампа маршрут печатей состав кран пакет отметка
лед протокар перрон штамп сигнал архив лента телеграфная нить
инк-станция бункер конвейер пломба манифест отсек верстак
ламповый щит диктофон шифр почерк чернила регистр ведомость
сундук сургуч компас перекрёсток фонарь калитка шлагбаум
журнал смена наряд отливка оттиск
""".split()

DAT_TILE = bytes(range(16)) * 4          # 64 B: values 0..15, no 0x53/0xEF
DAT_HEADER = b"CAM2050-0001\r\n\x00\x00"  # 16 B
DAT_SIZE = 41943040                      # 40 MiB


def make_png(width: int, height: int, rgb: tuple[int, int, int]) -> bytes:
    def chunk(tag: bytes, payload: bytes) -> bytes:
        body = tag + payload
        return struct.pack(">I", len(payload)) + body + struct.pack(
            ">I", zlib_crc(body)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    row = b"\x00" + bytes(rgb) * width
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(row * height))
        + chunk(b"IEND", b"")
    )


def zlib_crc(body: bytes) -> int:
    return zlib.crc32(body) & 0xFFFFFFFF


def gen_doc(rnd: random.Random) -> bytes:
    sents: list[str] = []
    while True:
        s = " ".join(rnd.choice(DOC_WORDS) for _ in range(rnd.randint(6, 10)))
        sents.append(s[0].upper() + s[1:] + ".")
        text = " ".join(sents)
        if len(text.encode("utf-8")) >= 1024 and len(text.encode("utf-8")) <= 4096:
            break
        if len(text.encode("utf-8")) > 4096:
            break
    return " ".join(sents)[:4096].encode("utf-8")


def collect_media(
    media_dir: Path | None,
) -> dict[str, list[tuple[str, Path]]]:
    """Split downloaded media into (fs path, local path) pairs per location.

    Location ``p1`` gets the first MEDIA_SPLIT files of each category,
    ``hidden`` — the rest.  No dir / missing category → empty lists
    (the build stays media-free, nothing breaks).
    """
    out: dict[str, list[tuple[str, Path]]] = {"p1": [], "hidden": []}
    if media_dir is None:
        return out
    for cat in MEDIA_CATEGORIES:
        cat_dir = media_dir / cat
        files = (
            sorted(cat_dir.iterdir(), key=lambda p: p.name)
            if cat_dir.is_dir()
            else []
        )
        for i, f in enumerate(files):
            if i < MEDIA_SPLIT:
                out["p1"].append((f"/home/crane/media/{cat}/{f.name}", f))
            else:
                out["hidden"].append((f"/{cat}/{f.name}", f))
    return out


def stage_p1_content(stage: Path) -> list[tuple[str, Path]]:
    """Create the staged files; return (fs path, local path) pairs."""
    rnd = random.Random(2050)
    (stage / "docs").mkdir(parents=True, exist_ok=True)
    (stage / "media").mkdir(parents=True, exist_ok=True)
    (stage / "README.txt").write_bytes(README_TXT.encode("utf-8"))
    (stage / "sticky.txt").write_bytes(STICKY_TXT.encode("utf-8"))
    (stage / "old-drive.txt").write_bytes(OLD_DRIVE_TXT.encode("utf-8"))
    (stage / "transcript.txt").write_bytes(TRANSCRIPT_TXT.encode("utf-8"))
    (stage / "bash_history").write_bytes(BASH_HISTORY.encode("utf-8"))
    (stage / "history.csv").write_bytes(HISTORY_CSV.encode("utf-8"))
    pairs: list[tuple[str, Path]] = [
        ("/home/crane/README.txt", stage / "README.txt"),
        ("/home/crane/notes/sticky.txt", stage / "sticky.txt"),
        ("/home/crane/notes/old-drive.txt", stage / "old-drive.txt"),
        ("/home/crane/chat/transcript.txt", stage / "transcript.txt"),
        ("/home/crane/.bash_history", stage / "bash_history"),
        ("/home/crane/browser/history.csv", stage / "history.csv"),
    ]
    for i in range(150):
        f = stage / "docs" / f"doc-{i:03d}.txt"
        f.write_bytes(gen_doc(rnd))
        pairs.append(("/home/crane/docs/doc-%03d.txt" % i, f))
    for i, rgb in enumerate(
        [(12, 24, 40), (90, 30, 20), (200, 180, 40), (40, 80, 60)], start=1
    ):
        f = stage / "media" / f"cam-{i:02d}.png"
        f.write_bytes(make_png(32, 32, rgb))
        pairs.append(("/home/crane/media/cam-%02d.png" % i, f))
    dat = stage / "media" / "courier-cam-2050.dat"
    body = DAT_SIZE - len(DAT_HEADER)
    dat.write_bytes(
        DAT_HEADER + DAT_TILE * (body // len(DAT_TILE)) + DAT_TILE[: body % len(DAT_TILE)]
    )
    pairs.append(("/home/crane/media/courier-cam-2050.dat", dat))
    return pairs


def parse_blocks_section(out: bytes) -> list[tuple[int, int]]:
    """Return (first, last) block ranges from a debugfs ``stat`` BLOCKS section.

    e2fsprogs >= 1.47 format:  ``BLOCKS:`` then one line per extent,
    ``(<ext>):<first>[-<last>]``, then ``TOTAL:``.
    """
    m = re.search(rb"BLOCKS:\n((?:\([^)]*\):\d+(?:-\d+)?\n)+)TOTAL:", out)
    if m is None:
        return []
    ranges: list[tuple[int, int]] = []
    for line in m.group(1).splitlines():
        lm = re.match(rb"\(\d+(?:-\d+)?\):(\d+)(?:-(\d+))?", line.strip())
        if lm:
            a = int(lm.group(1))
            ranges.append((a, int(lm.group(2) or a)))
    return ranges


# ------------------------------------------------------------- volume builders


def build_p1(tmp: Path, media: dict[str, list[tuple[str, Path]]]) -> Path:
    img = tmp / "p1.img"
    with open(img, "wb") as f:
        f.truncate(P1_SIZE)
    run(["mke2fs", "-F", "-q", "-t", "ext4", "-b", "1024", "-L", P1_LABEL, str(img)])
    stage = tmp / "p1-stage"
    stage.mkdir(exist_ok=True)
    pairs = stage_p1_content(stage)
    script = tmp / "p1.script"
    lines = [
        "mkdir /home",
        "mkdir /home/crane",
        "mkdir /home/crane/notes",
        "mkdir /home/crane/chat",
        "mkdir /home/crane/browser",
        "mkdir /home/crane/docs",
        "mkdir /home/crane/media",
    ]
    lines += [
        f"mkdir /home/crane/media/{cat}"
        for cat in MEDIA_CATEGORIES
        if any(dst.startswith(f"/home/crane/media/{cat}/") for dst, _ in media["p1"])
    ]
    # debugfs: write <source file on host> <destination name in fs>
    lines += [f"write {src} {dst}" for dst, src in pairs]
    lines += [f"write {src} {dst}" for dst, src in media["p1"]]
    script.write_text("\n".join(lines) + "\n")
    run(["debugfs", "-w", "-f", str(script), str(img)])
    return img


FAKE_TILE = (
    b"recovery partition - do not mount - recovery partition - " + b" " * 7
)[:64]
assert len(FAKE_TILE) == 64
assert 0x53 not in FAKE_TILE and all(b < 0x80 for b in FAKE_TILE)


def build_decoy(tmp: Path) -> Path:
    img = tmp / "fake.img"
    with open(img, "wb") as f:
        for _ in range(FAKE_SIZE // 64):
            f.write(FAKE_TILE)
        # planted fake superblock: zero the 1 KiB window, then fields
        f.seek(1024)
        f.write(b"\x00" * 1024)
        f.seek(SB_MAGIC)
        f.write(MAGIC)                                # +1080
        f.seek(SB_STATE)
        f.write(struct.pack("<H", 0x0000))            # +1082 state: not in use
        f.seek(SB_BLOCKS)
        f.write(struct.pack("<I", 0))                 # +1028 blocks_count: 0
        f.seek(SB_LABEL)
        f.write(FAKE_LABEL.encode().ljust(16, b"\x00"))  # +1144
    return img


def build_hidden(
    tmp: Path, media: dict[str, list[tuple[str, Path]]]
) -> tuple[Path, int]:
    """Build the hidden ext2 volume; return (image, first block of sealed.bin).

    ``debugfs write`` skips all-zero data blocks entirely (no allocation,
    no i_blocks), so ``sealed.bin`` is first seeded with one non-zero byte
    per 1 KiB block to force the four blocks to be allocated, then those
    exact blocks are zeroed in the image file — the finished file is a
    fully allocated, all-zero 4096 B file.
    """
    img = tmp / "hidden.img"
    with open(img, "wb") as f:
        f.truncate(HIDDEN_SIZE)
    run(["mke2fs", "-F", "-q", "-t", "ext2", "-b", "1024", "-L", HIDDEN_LABEL, str(img)])
    stage = tmp / "hidden-stage"
    stage.mkdir(exist_ok=True)
    (stage / "note.txt").write_bytes(NOTE_TXT.encode("utf-8"))
    (stage / "sealed.bin").write_bytes(
        (b"\x00" * (BLOCK - 1) + b"\x01") * (SEAL_SIZE // BLOCK)
    )
    script = tmp / "hidden.script"
    lines = [
        f"mkdir /{cat}"
        for cat in MEDIA_CATEGORIES
        if any(dst.startswith(f"/{cat}/") for dst, _ in media["hidden"])
    ]
    lines += [f"write {src} {dst}" for dst, src in media["hidden"]]
    lines += [
        f"write {stage / 'note.txt'} /note.txt",
        f"write {stage / 'sealed.bin'} /sealed.bin",
    ]
    script.write_text("\n".join(lines) + "\n")
    run(["debugfs", "-w", "-f", str(script), str(img)])
    out = run_out(["debugfs", "-R", "stat /sealed.bin", str(img)])
    ranges = parse_blocks_section(out)
    if len(ranges) != 1:
        sys.stderr.write(out.decode("utf-8", "replace"))
        raise RuntimeError(
            f"sealed.bin must occupy one contiguous extent, got {ranges}"
        )
    first, last = ranges[0]
    if last - first + 1 != SEAL_SIZE // BLOCK:
        raise RuntimeError(
            f"sealed.bin spans {last - first + 1} blocks, "
            f"expected {SEAL_SIZE // BLOCK} (must be contiguous for the manifest)"
        )
    with open(img, "r+b") as f:
        for b in range(first, last + 1):
            f.seek(b * BLOCK)
            f.write(b"\x00" * BLOCK)
    return img, first


# ------------------------------------------------------------------- assembly


def assemble(out_dir: Path, p1: Path, fake: Path, hidden: Path, manifest: dict) -> None:
    base = out_dir / IMG_NAME
    run(["dd", "if=/dev/zero", f"of={base}", "bs=1M", "count=256"])
    with open(base, "r+b") as f:
        f.write(build_mbr())
    run(["dd", f"if={p1}", f"of={base}", "bs=1M", "seek=1", "conv=notrunc"])
    run(["dd", f"if={fake}", f"of={base}", "bs=1M", "seek=129", "conv=notrunc"])
    run(["dd", f"if={hidden}", f"of={base}", "bs=1M", "seek=145", "conv=notrunc"])
    (out_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n")


def build(out_dir: Path, media_dir: Path | None = None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="btb-build-"))
    try:
        media = collect_media(media_dir)
        p1 = build_p1(tmp, media)
        fake = build_decoy(tmp)
        hidden, sealed_first = build_hidden(tmp, media)
        manifest = {
            "image_size": IMAGE_SIZE,
            "hidden_volume_offset": HIDDEN_OFF,
            "fake_volume_offset": FAKE_OFF,
            "sealed_bin_offset": HIDDEN_OFF + sealed_first * BLOCK,
            "sealed_bin_size": SEAL_SIZE,
            "media_p1_files": len(media["p1"]),
            "media_hidden_files": len(media["hidden"]),
            "media_bytes": sum(
                f.stat().st_size for _, f in media["p1"] + media["hidden"]
            ),
        }
        for key, loc in (("media_sample_p1", "p1"), ("media_sample_hidden", "hidden")):
            if media[loc]:
                dst, f = media[loc][0]
                manifest[key] = {"path": dst, "bytes": f.stat().st_size}
        assemble(out_dir, p1, fake, hidden, manifest)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# -------------------------------------------------------------------- verify


def verify(out_dir: Path) -> None:
    """Assert the assembled image is exactly what the player path needs."""
    base = out_dir / IMG_NAME
    img = base.read_bytes()
    n = 0

    def ck(cond: bool, name: str) -> None:
        nonlocal n
        if not cond:
            raise AssertionError(f"verify FAILED: {name}")
        n += 1
        print(f"  ok: {name}")

    ck(len(img) == IMAGE_SIZE, f"image size == {IMAGE_SIZE}")
    ck(img[510:512] == b"\x55\xAA", "MBR signature 0x55AA")
    ck(img[446] == 0x00, "MBR entry0 status free")
    ck(img[450] == 0x83, "MBR entry0 type 0x83")
    ck(
        struct.unpack_from("<II", img, 454) == (2048, P1_SIZE // 512),
        "MBR entry0 lba_start 2048 / lba_count 262144",
    )

    ck(img[P1_OFF + SB_MAGIC : P1_OFF + SB_MAGIC + 2] == MAGIC, "P1 ext4 magic")
    ck(
        img[P1_OFF + SB_LABEL : P1_OFF + SB_LABEL + 16].rstrip(b"\x00")
        == P1_LABEL.encode(),
        "P1 label",
    )

    ck(img[FAKE_OFF + SB_MAGIC : FAKE_OFF + SB_MAGIC + 2] == MAGIC, "decoy magic")
    ck(
        struct.unpack_from("<H", img, FAKE_OFF + SB_STATE)[0] == 0,
        "decoy state == 0 (not in use)",
    )
    ck(
        struct.unpack_from("<I", img, FAKE_OFF + SB_BLOCKS)[0] == 0,
        "decoy blocks_count == 0",
    )
    ck(
        img[FAKE_OFF + SB_LABEL : FAKE_OFF + SB_LABEL + 16].rstrip(b"\x00")
        == FAKE_LABEL.encode(),
        "decoy label",
    )

    ck(img[HIDDEN_OFF + SB_MAGIC : HIDDEN_OFF + SB_MAGIC + 2] == MAGIC, "hidden magic")
    ck(
        bool(struct.unpack_from("<H", img, HIDDEN_OFF + SB_STATE)[0] & 1),
        "hidden state in-use",
    )
    ck(
        struct.unpack_from("<I", img, HIDDEN_OFF + SB_BLOCKS)[0] == HIDDEN_SIZE // BLOCK,
        "hidden blocks_count == 113664",
    )
    ck(
        img[HIDDEN_OFF + SB_LABEL : HIDDEN_OFF + SB_LABEL + 16].rstrip(b"\x00")
        == HIDDEN_LABEL.encode(),
        "hidden label",
    )

    manifest = json.loads((out_dir / MANIFEST_NAME).read_text())
    off = manifest["sealed_bin_offset"]
    ck(img[off : off + SEAL_SIZE] == b"\x00" * SEAL_SIZE, "sealed.bin area all zeros")

    # cross-check the manifest against the real fs layout: slice the hidden
    # volume out and ask debugfs where sealed.bin actually lives
    tmp = Path(tempfile.mkdtemp(prefix="btb-verify-"))
    try:
        vol = tmp / "hidden-slice.img"
        vol.write_bytes(img[HIDDEN_OFF : HIDDEN_OFF + HIDDEN_SIZE])
        out = run_out(["debugfs", "-R", "stat /sealed.bin", str(vol)])
        ranges = parse_blocks_section(out)
        ck(
            len(ranges) == 1
            and ranges[0][0] == (off - HIDDEN_OFF) // BLOCK
            and ranges[0][1] - ranges[0][0] + 1 == SEAL_SIZE // BLOCK,
            "manifest offset == fs block (single contiguous extent)",
        )
        out = run_out(["debugfs", "-R", "cat /note.txt", str(vol)])
        ck(
            ("Код к файлу sealed.bin: " + CODE).encode("utf-8") in out,
            "note.txt carries the code line",
        )
        out = run_out(["debugfs", "-R", "cat /sealed.bin", str(vol)])
        ck(len(out) == SEAL_SIZE and out == b"\x00" * SEAL_SIZE, "debugfs cat sealed")

        # decoy media: each embedded sample must be readable byte-for-byte
        for key, voff, vsize in (
            ("media_sample_p1", P1_OFF, P1_SIZE),
            ("media_sample_hidden", HIDDEN_OFF, HIDDEN_SIZE),
        ):
            sample = manifest.get(key)
            if not sample:
                continue
            slice_path = tmp / f"{key}.img"
            slice_path.write_bytes(img[voff : voff + vsize])
            out = run_out(
                ["debugfs", "-R", f"cat {sample['path']}", str(slice_path)]
            )
            ck(
                len(out) == sample["bytes"],
                f"{key}: debugfs cat {sample['path']} ({sample['bytes']} B)",
            )
            slice_path.unlink()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"verify: {n} checks passed")


# --------------------------------------------------------------------- main


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument(
        "--media-dir",
        default=None,
        help="directory with downloaded decoy media (photos/ music/ video/),"
        " as produced by download_media.py; omit for a media-free image",
    )
    ap.add_argument(
        "--verify",
        action="store_true",
        help="after the build, assert the image layout (self-check gate)",
    )
    a = ap.parse_args()
    out = Path(a.out)
    build(out, Path(a.media_dir) if a.media_dir else None)
    if a.verify:
        verify(out)
    print(f"built {out / IMG_NAME} ({IMAGE_SIZE} bytes) + {out / MANIFEST_NAME}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
