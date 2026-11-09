
from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import Dict, List, Tuple

MAGIC = b"FWM2"
VERSION = 2
HEADER = struct.Struct("<4sHHIIIIIII")
HEADER_SIZE = HEADER.size
KEY = 0x4C554D4E  
FLAGS = 1
MAX_CODE = 1024
MAX_CONST = 512
MAX_IMAGE = HEADER_SIZE + MAX_CODE + MAX_CONST



OP_NOP = 0x00
OP_MOVI = 0x01
OP_MOV = 0x02
OP_ADD = 0x03
OP_SUB = 0x04
OP_MUL = 0x05
OP_DIV = 0x06
OP_MOD = 0x07
OP_CMP_EQ = 0x08
OP_JNZ = 0x09
OP_JMP = 0x0A
OP_OUT = 0x0B
OP_OUTHEX = 0x0C
OP_PICK = 0x0D
OP_PUT = 0x0E
OP_HALT = 0x0F
OP_XOR = 0x10
OP_AND = 0x11
OP_SHL = 0x12
OP_OR = 0x13


def _mask_byte(key: int, index: int) -> int:
    
    
    lane = (key >> ((index & 3) * 8)) & 0xFF
    return (lane + index * 0x3D + ((index >> 2) * 0x17)) & 0xFF


def crypt(payload: bytes, key: int = KEY) -> bytes:
    return bytes(value ^ _mask_byte(key, i) for i, value in enumerate(payload))


def build_image(code: bytes, const: bytes = b"", *, entry: int = 0,
                key: int = KEY, flags: int = FLAGS) -> bytes:
    if not code or len(code) > MAX_CODE:
        raise ValueError("bad code length")
    if len(const) > MAX_CONST:
        raise ValueError("bad const length")
    if not (0 <= entry < len(code)):
        raise ValueError("bad entry")
    plain = code + const
    crc = zlib.crc32(plain) & 0xFFFFFFFF
    header = HEADER.pack(
        MAGIC,
        VERSION,
        HEADER_SIZE,
        len(code),
        len(const),
        entry,
        flags,
        crc,
        key & 0xFFFFFFFF,
        0,
    )
    return header + crypt(plain, key)


class Assembler:

    def __init__(self) -> None:
        self.code = bytearray()
        self.labels: Dict[str, int] = {}
        self.fixups: List[Tuple[int, str, int]] = []

    def label(self, name: str) -> "Assembler":
        if name in self.labels:
            raise ValueError(f"duplicate label: {name}")
        self.labels[name] = len(self.code)
        return self

    def emit(self, *values: int) -> "Assembler":
        self.code.extend(value & 0xFF for value in values)
        return self

    def movi(self, dst: int, value: int) -> "Assembler":
        self.emit(OP_MOVI, dst)
        self.code.extend(struct.pack("<q", value))
        return self

    def mov(self, dst: int, src: int) -> "Assembler":
        return self.emit(OP_MOV, dst, src)

    def arith(self, op: int, dst: int, left: int, right: int) -> "Assembler":
        return self.emit(op, dst, left, right)

    def cmp_eq(self, dst: int, left: int, right: int) -> "Assembler":
        return self.arith(OP_CMP_EQ, dst, left, right)

    def jnz(self, reg: int, label: str) -> "Assembler":
        at = len(self.code)
        self.emit(OP_JNZ, reg, 0)
        self.fixups.append((at + 2, label, at + 3))
        return self

    def jmp(self, label: str) -> "Assembler":
        at = len(self.code)
        self.emit(OP_JMP, 0)
        self.fixups.append((at + 1, label, at + 2))
        return self

    def pick(self, dst: int, slot: int) -> "Assembler":
        return self.emit(OP_PICK, dst, slot)

    def put(self, slot: int, src: int) -> "Assembler":
        return self.emit(OP_PUT, slot, src)

    def out(self, reg: int) -> "Assembler":
        return self.emit(OP_OUT, reg)

    def outhex(self, reg: int) -> "Assembler":
        return self.emit(OP_OUTHEX, reg)

    def halt(self, reg: int) -> "Assembler":
        return self.emit(OP_HALT, reg)

    def finish(self) -> bytes:
        for position, label, base in self.fixups:
            if label not in self.labels:
                raise ValueError(f"unknown label: {label}")
            rel = self.labels[label] - base
            if not -128 <= rel <= 127:
                raise ValueError(f"jump out of range: {label}")
            self.code[position] = rel & 0xFF
        return bytes(self.code)


def stock_code() -> bytes:
    a = Assembler()
    
    
    a.pick(7, 8).put(8, 7)

    
    
    
    operations = (
        (0, OP_ADD, "add"),
        (1, OP_SUB, "sub"),
        (2, OP_MUL, "mul"),
        (3, OP_DIV, "div"),
        (4, OP_MOD, "mod"),
        (5, OP_OR, "or"),
        (6, OP_AND, "and"),
        (7, OP_XOR, "xor"),
    )
    for operation, opcode, name in operations:
        body = f"{name}_body"
        next_check = f"{name}_next"
        a.movi(3, operation).cmp_eq(4, 2, 3).jnz(4, body).jmp(next_check)
        a.label(body).arith(opcode, 6, 0, 1).halt(6)
        a.label(next_check)

    
    a.movi(6, 0).halt(6)
    return a.finish()


if __name__ == "__main__":
    output = Path(__file__).with_name("default.fw")
    output.write_bytes(build_image(stock_code(), b"FASTCALC\x00"))
    print(f"wrote {output} ({output.stat().st_size} bytes)")
