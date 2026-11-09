#!/usr/bin/env python3
"""«Чёрный палец» — forensic-ридер образа USB-носителя (pure stdlib).

Цепочка решения (Task 4): скачать 256 MiB-образ → MBR (по таблице один
том) → скан ext2-томов по 1 МиБ-границам (приманка «recovery» — фейк:
state=0, blocks=0) → настоящий том: note.txt (код) + sealed.bin
(архив с паролем) → флаг.

Идея решения по шагам:
1. Скачать/прочитать образ и распаковать gzip → raw 256 MiB.
2. MBR показывает один том на 1..129 MiB — образ вдвое длиннее, значит
   за концом партиции есть скрытая область, невидимая для таблицы.
3. Скан хвоста по 1 МиБ-границам: магия ext2 (0xEF53) в суперблоке +
   непустой label → кандидаты (приманка и backup-копии тоже попадают).
4. Дискриминация: настоящий том чисто размонтирован (state=1) и его длина
   blocks*bs точно занимает остаток образа — остальные кандидаты отпадают.
5. Свой ext2-ридер (суперблок → дескриптор группы → inode → direct blocks
   → dir entries) читает из корня note.txt — там код к sealed.bin.
6. sealed.bin — ZIP с ZipCrypto; пароль = код из note.txt → внутри flag.txt.

Офсеты полей — эмпирически проверены 2026-10-24 против mke2fs 1.47
(e2fsprogs, Ubuntu 24.04) на образе с блоками 1 KiB, cross-check с
debugfs stat/cat:
  superblock (том+1024): s_blocks_count@+4, s_log_block_size@+24,
    s_blocks_per_group@+32, s_inodes_per_group@+36, s_magic@+56
    (abs +1080), s_state@+58, s_inode_size@+88, s_uuid@+104,
    s_volume_name@+120 (16 B, NUL-заполнен);
  group descriptor table (блок 2): descriptor 64 B,
    bg_inode_table@+8 (у e2fsprogs 1.47 для 1 KiB размер descriptor'а
    из суперблока не читается — проверено: descriptor группы 1 стоит
    на GDT+64, bb/ib/table 16385-16387 — в блоковой группе 1
    9216..17407; вариант 32 B даёт 8451-8453 — в группе 0, невозможно);
  inode (256 B): i_size@+4, i_block[0..11]@+40 (+4k) — direct,
    номера блоков абсолютные от начала тома;
  dir entry: inode@+0, rec_len@+4, name_len@+6, ftype@+7, name@+8.
"""

import struct

MB = 1024 * 1024
EXT_MAGIC = 0xEF53
DESC_SIZE = 64          # group descriptor, см. docstring


def parse_mbr(data: bytes) -> list[tuple[int, int, int]]:
    """4 записи MBR: (type, lba_start, lba_count)."""
    # таблица разделов: смещение 446, 4 записи по 16 байт;
    # в каждой: type@+4, lba_start@+8, lba_count@+12 (little-endian u32)
    if len(data) < 512 or data[510:512] != b"\x55\xaa":
        raise ValueError("not an MBR (no 0x55AA signature)")
    return [
        (
            data[446 + 16 * i + 4],
            struct.unpack_from("<I", data, 446 + 16 * i + 8)[0],
            struct.unpack_from("<I", data, 446 + 16 * i + 12)[0],
        )
        for i in range(4)
    ]


def ext2_sb(volume: bytes) -> dict:
    """Superblock ext2/ext4 (1 KiB блок на том+1024).

    Поля читаются как есть — без фильтрации по magic: дискриминация
    кандидатов (magic/state/длина) — дело вызывающего кода.
    """
    if len(volume) < 1024 + 136:
        raise ValueError("volume too small for an ext2 superblock")
    sb = volume[1024:1024 + 1024]
    return {
        "magic": struct.unpack_from("<H", sb, 56)[0],
        "state": struct.unpack_from("<H", sb, 58)[0],
        "blocks": struct.unpack_from("<I", sb, 4)[0],
        "log_block_size": struct.unpack_from("<I", sb, 24)[0],
        "blocks_per_group": struct.unpack_from("<I", sb, 32)[0],
        "inodes_per_group": struct.unpack_from("<I", sb, 36)[0],
        "inode_size": struct.unpack_from("<H", sb, 88)[0],
        "uuid": sb[104:120],
        "volume_name": sb[120:136].rstrip(b"\x00"),
    }


def find_ext2_volumes(data: bytes, from_off: int) -> list[int]:
    """Суперблоки ext2/ext4 на 1 МиБ-границах (фиксированные позиции,
    не скользящий скан): magic 0xEF53 на +1080 и непустой label
    (s_volume_name, +1144).

    state НЕ фильтрует: приманка «recovery» (state=0) тоже
    возвращается — дискриминация ((state & 1) and
    blocks * bs == len(data) - off) — у вызывающего.

    В скан также попадают backup-копии суперблока ВНУТРИ найденного
    тома (e2fsprogs кладёт их на группах; у e2fsprogs 1.47 с
    1 KiB блоками — state=0, те же blocks/uuid/label): они
    проигрывают дискриминацию и по state, и по длине.
    """
    out = []
    # старт скана — округление вверх до 1 МиБ-границы (тома кладут на границу)
    off = ((max(from_off, 0) + MB - 1) // MB) * MB
    while off + 1160 <= len(data):
        if data[off + 1080:off + 1082] == b"\x53\xef":
            if data[off + 1144:off + 1160].rstrip(b"\x00"):
                out.append(off)
        off += MB
    return out


def _inode(volume: bytes, sb: dict, bs: int, ino: int) -> tuple[int, list[int]]:
    """(i_size, i_block[0..11]) инода ino (direct blocks, ext2)."""
    # иноды нумеруются с 1; группа = (ino-1) // inodes_per_group
    group = (ino - 1) // sb["inodes_per_group"]
    # таблица дескрипторов групп — блок 2; bg_inode_table — поле +8 дескриптора
    table = struct.unpack_from("<I", volume, 2 * bs + group * DESC_SIZE + 8)[0]
    o = table * bs + (ino - 1) * sb["inode_size"]
    if o + sb["inode_size"] > len(volume):
        raise ValueError("inode table out of range")
    size = struct.unpack_from("<I", volume, o + 4)[0]
    blocks = [
        struct.unpack_from("<I", volume, o + 40 + 4 * k)[0] for k in range(12)
    ]
    return size, blocks


def _blocks_to_data(volume: bytes, bs: int, size: int, blocks: list[int]) -> bytes:
    """Склейка direct-блоков, обрезка до size."""
    out = bytearray()
    for b in blocks:
        # блок 0 — «дыра» (sparse) или конец direct-цепочки: дальше не читаем
        if not b or len(out) >= size:
            break
        take = min(bs, size - len(out))
        if b * bs + take > len(volume):
            raise ValueError("data block out of range")
        out += volume[b * bs:b * bs + take]
    return bytes(out)


def _read_dir(volume: bytes, sb: dict, bs: int, ino: int) -> list[tuple[int, int, bytes]]:
    """Записи каталога ino: (ino, ftype, name) — ext2 dir entry."""
    size, blocks = _inode(volume, sb, bs, ino)
    data = _blocks_to_data(volume, bs, size, blocks)
    out = []
    off = 0
    while off + 8 <= len(data):
        rec_len = struct.unpack_from("<H", data, off + 4)[0]
        if rec_len < 8 or off + rec_len > len(data):
            break
        entry_ino = struct.unpack_from("<I", data, off)[0]
        nlen = data[off + 6]
        # inode 0 — стёртая запись (хвост rec_len), пропускаем
        if entry_ino:
            out.append((entry_ino, data[off + 7], data[off + 8:off + 8 + nlen]))
        off += rec_len
    return out


def read_ext2_file(volume: bytes, name: str) -> bytes:
    """Содержимое файла name из корневой директории тома (inode 2)."""
    sb = ext2_sb(volume)
    if sb["magic"] != EXT_MAGIC:
        raise ValueError("not an ext2/ext4 volume (s_magic != 0xEF53)")
    for field in ("blocks", "blocks_per_group", "inodes_per_group", "inode_size"):
        if not sb[field]:
            raise ValueError("corrupt superblock: %s = 0" % field)
    bs = 1024 << sb["log_block_size"]
    target = None
    # корень ext2 — inode 2; ftype 1 — обычный файл
    for ino, ftype, entry in _read_dir(volume, sb, bs, 2):
        if ftype == 1 and entry == name.encode("utf-8"):
            target = ino
            break
    if target is None:
        raise KeyError(name)
    size, blocks = _inode(volume, sb, bs, target)
    return _blocks_to_data(volume, bs, size, blocks)


def main() -> None:
    """Тело solвера: download → gunzip → MBR → tail-scan → дискриминация
    → slice → reader → zip(код из note.txt) → флаг.

    target: URL живого инстанса (…/download/black-thumb.img.gz или корень),
    локальный .gz либо raw-образ.
    """
    import gzip
    import io
    import re
    import sys
    import urllib.request
    import zipfile

    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13445"
    if target.startswith("http://") or target.startswith("https://"):
        url = target if target.endswith(".gz") else target.rstrip("/") + "/download/black-thumb.img.gz"
        raw = urllib.request.urlopen(url).read()
        data = gzip.decompress(raw)
    elif target.endswith(".gz"):
        data = gzip.decompress(open(target, "rb").read())
    else:
        data = open(target, "rb").read()

    # 1) MBR: один том (0x83) — «стол врёт»: дальше образ не закончен
    p1 = parse_mbr(data)[0]
    tail = (p1[1] + p1[2]) * 512  # конец P1 = начало хвоста (129 MiB)
    assert len(data) > tail, "image ends at the declared partition"

    # 2) скан ext2-томов по хвосту + дискриминация:
    #    (state & 1) and blocks * bs == остатку образа → единственный том
    cands = find_ext2_volumes(data, tail)
    real = None
    for c in cands:
        sb = ext2_sb(data[c:])
        bs = 1024 << sb["log_block_size"]
        if (sb["state"] & 1) and sb["blocks"] * bs == len(data) - c:
            real = c
            break
    assert real is not None, "no real ext2 volume in the tail: %r" % cands

    # 3) note.txt → код; sealed.bin → zip (ZipCrypto, тот же код)
    #    (note — str: bytes-литерал regex c кириллицей невалиден)
    # срез тома по длине из суперблока (bs = 1 KiB → blocks * 1024)
    vol = data[real:real + ext2_sb(data[real:])["blocks"] * 1024]
    note = read_ext2_file(vol, "note.txt").decode("utf-8")
    code = re.search(r"Код к файлу sealed\.bin:\s*(\S+)", note).group(1)
    sealed = read_ext2_file(vol, "sealed.bin")
    z = zipfile.ZipFile(io.BytesIO(sealed))
    z.setpassword(code.encode())
    print(z.read("flag.txt").decode().strip())


if __name__ == "__main__":
    main()
