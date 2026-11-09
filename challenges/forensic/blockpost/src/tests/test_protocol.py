import unittest
import zlib

from mc_blockpost.protocol import (
    ID, block_update, decode_position, encode_position, frame,
    read_varint, unframe, write_varint,
)


class VarIntTest(unittest.TestCase):
    VALUES = [0, 1, 127, 128, 255, 2097151, -1, 25565, 2**31 - 1, -2**31]

    def test_roundtrip(self):
        for v in self.VALUES:
            with self.subTest(v=v):
                enc = write_varint(v)
                self.assertEqual(read_varint(enc, 0), (v, len(enc)))

    def test_known_encodings(self):
        # эталонные байты из спецификации протокола
        self.assertEqual(write_varint(0), b"\x00")
        self.assertEqual(write_varint(127), b"\x7f")
        self.assertEqual(write_varint(128), b"\x80\x01")
        self.assertEqual(write_varint(255), b"\xff\x01")
        self.assertEqual(write_varint(2097151), b"\xff\xff\x7f")
        self.assertEqual(write_varint(-1), b"\xff\xff\xff\xff\x0f")

    def test_offset(self):
        buf = b"\xaa" + write_varint(300) + b"\xbb"
        self.assertEqual(read_varint(buf, 1), (300, 3))

    def test_too_big(self):
        with self.assertRaises(ValueError):
            read_varint(b"\xff" * 6, 0)


class PositionTest(unittest.TestCase):
    CASES = [
        (0, 0, 0), (120, 70, 64), (-1, -1, -1), (-200, 50, 400),
        (400, -64, -200), (33554431, 2047, 33554431), (-33554432, -2048, -33554432),
        (18357644, 831, -20882616),  # пример из wiki.vg
    ]

    def test_roundtrip(self):
        for x, y, z in self.CASES:
            with self.subTest(pos=(x, y, z)):
                enc = encode_position(x, y, z)
                self.assertEqual(len(enc), 8)
                self.assertEqual(decode_position(enc), (x, y, z))

    def test_bit_layout(self):
        v = int.from_bytes(encode_position(1, 2, 3), "big")
        self.assertEqual(v, (1 << 38) | (3 << 12) | 2)


class IdTableTest(unittest.TestCase):
    def test_wiki_ids(self):
        # сверено с minecraft.wiki, Java Edition protocol 777 (26.3)
        self.assertEqual(ID.L_CB_ENCRYPTION_REQUEST, 0x01)
        self.assertEqual(ID.L_CB_SET_COMPRESSION, 0x03)
        self.assertEqual(ID.C_CB_FINISH, 0x03)
        self.assertEqual(ID.P_CB_BLOCK_UPDATE, 0x08)
        self.assertEqual(ID.P_CB_LOGIN, 0x32)
        self.assertEqual(ID.P_CB_CHUNK_DATA, 0x2E)
        self.assertEqual(ID.P_SB_USE_ITEM_ON, 0x42)


class FrameTest(unittest.TestCase):
    def test_plain(self):
        f = block_update(120, 70, 64, 0x4D)
        self.assertEqual(f[0], len(f) - 1)                 # Length = id + data
        pid, data, end = unframe(f, 0)
        self.assertEqual((pid, end), (ID.P_CB_BLOCK_UPDATE, len(f)))
        self.assertEqual(decode_position(data[:8]), (120, 70, 64))
        self.assertEqual(read_varint(data, 8)[0], 0x4D)

    def test_compressed_both_paths(self):
        small = frame(0x03, b"", threshold=8)              # меньше порога: Data Length = 0
        self.assertEqual(small, b"\x02\x00\x03")
        big = frame(0x2D, b"\x01" * 40, threshold=8)       # сжат zlib
        length, o = read_varint(big, 0)
        data_len, o2 = read_varint(big, o)
        self.assertEqual(data_len, 41)
        self.assertEqual(zlib.decompress(big[o2:]), b"\x2d" + b"\x01" * 40)
        stream = small + big
        pid1, d1, off = unframe(stream, 0, threshold=8)
        pid2, d2, off = unframe(stream, off, threshold=8)
        self.assertEqual((pid1, d1, pid2, d2, off), (0x03, b"", 0x2D, b"\x01" * 40, len(stream)))

    def test_truncated(self):
        f = block_update(1, 2, 3, 4)
        with self.assertRaises(IndexError):
            unframe(f[:-1], 0)


if __name__ == "__main__":
    unittest.main()
