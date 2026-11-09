"""Сериализация типов данных протокола (кроме VarInt/Position — они в protocol.py)."""

import json
import struct
import uuid as _uuid

from .protocol import write_varint


def string(s: str) -> bytes:
    b = s.encode("utf-8")
    return write_varint(len(b)) + b


def identifier(s: str) -> bytes:
    return string(s if ":" in s else "minecraft:" + s)


def boolean(v: bool) -> bytes:
    return b"\x01" if v else b"\x00"


def byte(v: int) -> bytes:
    return struct.pack(">b", v)


def ubyte(v: int) -> bytes:
    return struct.pack(">B", v)


def short(v: int) -> bytes:
    return struct.pack(">h", v)


def ushort(v: int) -> bytes:
    return struct.pack(">H", v)


def int32(v: int) -> bytes:
    return struct.pack(">i", v)


def long(v: int) -> bytes:
    return struct.pack(">q", v)


def ulong(v: int) -> bytes:
    return struct.pack(">Q", v)


def f32(v: float) -> bytes:
    return struct.pack(">f", v)


def f64(v: float) -> bytes:
    return struct.pack(">d", v)


def uuid(u) -> bytes:
    return (u if isinstance(u, _uuid.UUID) else _uuid.UUID(u)).bytes


def byte_array(b: bytes) -> bytes:
    """Prefixed Array of Byte."""
    return write_varint(len(b)) + b


def prefixed(items, enc=lambda x: x) -> bytes:
    """Prefixed Array: VarInt count + элементы."""
    items = list(items)
    return write_varint(len(items)) + b"".join(enc(i) for i in items)


def optional(v, enc=lambda x: x) -> bytes:
    """Prefixed Optional: Boolean present + значение."""
    return b"\x00" if v is None else b"\x01" + enc(v)


def json_text(obj) -> bytes:
    return string(json.dumps(obj, separators=(",", ":"), ensure_ascii=False))


# --- сетевой NBT (безымянный корень, 1.20.2+) — для текстовых компонентов ---
def _nbt_string_payload(s: str) -> bytes:
    b = s.encode("utf-8")
    return ushort(len(b)) + b


def nbt_text(text: str, color: str = None) -> bytes:
    """Текстовый компонент как NBT. Простой текст — TAG_String, с цветом — TAG_Compound."""
    if color is None:
        return b"\x08" + _nbt_string_payload(text)
    body = b"\x08" + _nbt_string_payload("text") + _nbt_string_payload(text)
    body += b"\x08" + _nbt_string_payload("color") + _nbt_string_payload(color)
    return b"\x0a" + body + b"\x00"
