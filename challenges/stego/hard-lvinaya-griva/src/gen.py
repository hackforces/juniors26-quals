import binascii
import struct
import zlib
from pathlib import Path


def chunk(kind, data):
    checksum = binascii.crc32(kind + data) & 0xFFFFFFFF
    return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", checksum)


def build(flag, root):
    out = root / "download"
    out.mkdir(parents=True, exist_ok=True)
    width = height = 128
    compressed = zlib.compress(flag.encode(), level=9)
    bits = "".join(f"{byte:08b}" for byte in compressed)
    raw = bytearray()
    bit_index = 0
    mask_bits = 0
    for y in range(height):
        raw.append(0)
        for x in range(width):
            selected = (x * x + y * y) % 7 == 3
            red = ((x * 2) & 254) | int(selected)
            green = (y * 2) & 255
            blue = ((x + y) * 3) & 254
            if selected:
                mask_bits += 1
                if bit_index < len(bits):
                    blue |= int(bits[bit_index])
                    bit_index += 1
            raw.extend((red, green, blue))

    if bit_index != len(bits):
        raise RuntimeError("image is too small for the personal payload")
    if len(bits) * 2 > mask_bits:
        raise RuntimeError(
            "selection mask carries %d bits, under 2x headroom for the %d-bit payload"
            % (mask_bits, len(bits))
        )
    note = (
        b"restoration\0Red fibres mark the blue fibres to trust; read them in scan "
        b"order. The recovered thread was folded by the coast terminal."
    )
    data = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"tEXt", note)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )
    (out / "coast.png").write_bytes(data)
