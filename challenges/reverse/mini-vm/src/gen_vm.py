#!/usr/bin/env python3
"""
gen_vm.py - build-time generator for the mini-vm challenge binary.

The binary is a *forward oracle* for the custom permutation P defined in
spn.py: given a 16-byte block (32 hex chars) it prints P(block) (32 hex chars).
It contains NO flag and NO secret - the flag lives only in the challenge
server's environment and is handed out when the player inverts a fresh P(x0).

This script emits src/vm_blob.h, which carries:

  * vm_code_enc  - the VM bytecode, rolling-XOR encrypted (layer 1).
                   Decrypted, it is only a tiny UNPACK stub + a zero-filled
                   region; the real SPN program is NOT here.
  * vm_mem_init  - VM data memory: S-box, GF(2^8) *2/*3 tables, round
                   constants, a hex table, scratch, and the *packed* SPN
                   program (layer 2: XORed with a splitmix64 keystream).
                   At run time UNPACK rewrites the zero region of the code
                   with the de-obfuscated SPN body (self-modifying code).
  * vm_op_dec    - the per-build opcode-decode table (polymorphic ISA:
                   on-wire opcode bytes are a random permutation each build),
                   itself lightly XOR-obfuscated.
  * vm_code_sha  - SHA-256 of (decrypted code || mem_init) for anti-tamper.
                   Any patch silently corrupts the S-box lookups -> wrong P.
  * xs_err       - single-byte-XOR-obfuscated error string.

Usage: python3 gen_vm.py [SEED]
  SEED (int or hex) picks the S-box/constants; default is reproducible.
"""

import hashlib
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from spn import Params, BLOCK, DEFAULT_SEED

M64 = (1 << 64) - 1

XOR_KEY0 = 0x5A          # rolling key for the code at rest (layer 1)
STR_XOR = 0x5A           # obfuscation for strings and the opcode table
UNPACK_SEED = 0x9E3779B97F4A7C15  # splitmix64 seed for the pack keystream (layer 2)

# --------------------------------------------------------------------------- #
# Canonical VM ISA (chal.c switch + disasm mirror this; the ON-WIRE byte for
# each opcode is randomised per build via the vm_op_dec table).
# --------------------------------------------------------------------------- #
(NOP, PUSH, POP, DUP, SWAP, LOADIN, LDB, STB, ADD, SUB,
 XOR, AND, SHL, SHR, EQ, UNPACK, PRINT, EXIT) = range(18)

OPERAND_LEN = {
    NOP: 0, PUSH: 8, POP: 0, DUP: 0, SWAP: 0, LOADIN: 1, LDB: 0, STB: 0,
    ADD: 0, SUB: 0, XOR: 0, AND: 0, SHL: 0, SHR: 0, EQ: 0,
    UNPACK: 6, PRINT: 4, EXIT: 1,
}
NUM_OPS = 18


def mix64(z: int) -> int:
    z = (z + 0x9E3779B97F4A7C15) & M64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
    return z ^ (z >> 31)


def pack_keystream(n: int) -> bytes:
    """splitmix64 byte stream (must match OP_UNPACK in chal.c)."""
    out = bytearray()
    st = UNPACK_SEED
    for i in range(n):
        if i % 8 == 0:
            st = mix64(st)
        out.append((st >> (8 * (i % 8))) & 0xFF)
    return bytes(out)


class Asm:
    """Emits encoded (polymorphic) opcode bytes + little-endian operands."""

    def __init__(self, enc):
        self.enc = enc
        self.b = bytearray()

    def op(self, canonical):
        self.b.append(self.enc[canonical])

    def push(self, v):
        self.op(PUSH)
        self.b += struct.pack('<Q', v & M64)

    def loadin(self, i):
        self.op(LOADIN)
        self.b.append(i & 0xFF)

    def print_(self, off, length):
        self.op(PRINT)
        self.b += struct.pack('<HH', off, length)

    def exit_(self, code):
        self.op(EXIT)
        self.b.append(code & 0xFF)


def build_spn_body(enc, off, P: Params) -> bytes:
    """Emit the SPN forward program over a 16-byte block held in mem[STATE]."""
    SBOX, MUL2, MUL3 = off['SBOX'], off['MUL2'], off['MUL3']
    HEXTAB, RCON = off['HEXTAB'], off['RCON']
    STATE, TMP, HEXOUT = off['STATE'], off['TMP'], off['HEXOUT']
    a = Asm(enc)

    # state[i] = input[i]
    for i in range(16):
        a.loadin(i)                      # value
        a.push(STATE + i); a.op(STB)

    def sub_bytes():
        for i in range(16):
            a.push(STATE + i); a.op(LDB)             # s
            a.push(SBOX); a.op(ADD); a.op(LDB)       # SBOX[s]
            a.push(STATE + i); a.op(STB)

    def add_rc(r):
        for i in range(16):
            a.push(STATE + i); a.op(LDB)
            a.push(RCON + 16 * r + i); a.op(LDB)
            a.op(XOR)
            a.push(STATE + i); a.op(STB)

    def shift_rows():
        from spn import SR_SRC
        for i in range(16):                          # TMP[i] = STATE[src[i]]
            a.push(STATE + SR_SRC[i]); a.op(LDB)
            a.push(TMP + i); a.op(STB)
        for i in range(16):                          # STATE <- TMP
            a.push(TMP + i); a.op(LDB)
            a.push(STATE + i); a.op(STB)

    def term_mul(table, idx):                        # push table[STATE[idx]]
        a.push(table); a.push(STATE + idx); a.op(LDB); a.op(ADD); a.op(LDB)

    def term_plain(idx):                             # push STATE[idx]
        a.push(STATE + idx); a.op(LDB)

    def mix_cols():
        for c in range(4):
            base = 4 * c
            # out0 = 2a ^ 3b ^ c ^ d
            term_mul(MUL2, base + 0); term_mul(MUL3, base + 1); a.op(XOR)
            term_plain(base + 2); a.op(XOR); term_plain(base + 3); a.op(XOR)
            a.push(TMP + base + 0); a.op(STB)
            # out1 = a ^ 2b ^ 3c ^ d
            term_plain(base + 0); term_mul(MUL2, base + 1); a.op(XOR)
            term_mul(MUL3, base + 2); a.op(XOR); term_plain(base + 3); a.op(XOR)
            a.push(TMP + base + 1); a.op(STB)
            # out2 = a ^ b ^ 2c ^ 3d
            term_plain(base + 0); term_plain(base + 1); a.op(XOR)
            term_mul(MUL2, base + 2); a.op(XOR); term_mul(MUL3, base + 3); a.op(XOR)
            a.push(TMP + base + 2); a.op(STB)
            # out3 = 3a ^ b ^ c ^ 2d
            term_mul(MUL3, base + 0); term_plain(base + 1); a.op(XOR)
            term_plain(base + 2); a.op(XOR); term_mul(MUL2, base + 3); a.op(XOR)
            a.push(TMP + base + 3); a.op(STB)
        for i in range(16):                          # STATE <- TMP
            a.push(TMP + i); a.op(LDB)
            a.push(STATE + i); a.op(STB)

    for r in range(P.rounds):
        add_rc(r)
        sub_bytes()
        shift_rows()
        mix_cols()
    add_rc(P.rounds)                                 # final AddRoundConstant

    # hex-encode STATE into HEXOUT and print
    for i in range(16):
        a.push(HEXTAB); a.push(STATE + i); a.op(LDB)     # hi nibble
        a.push(4); a.op(SHR); a.op(ADD); a.op(LDB)
        a.push(HEXOUT + 2 * i); a.op(STB)
        a.push(HEXTAB); a.push(STATE + i); a.op(LDB)     # lo nibble
        a.push(0xF); a.op(AND); a.op(ADD); a.op(LDB)
        a.push(HEXOUT + 2 * i + 1); a.op(STB)
    a.push(ord('\n')); a.push(HEXOUT + 32); a.op(STB)
    a.print_(HEXOUT, 33)
    a.exit_(0)
    return bytes(a.b)


def gen(seed: int) -> None:
    P = Params(seed)

    # ---- memory layout (byte offsets) ------------------------------------ #
    off = {}
    cur = 0
    for name, size in [('SBOX', 256), ('MUL2', 256), ('MUL3', 256),
                       ('HEXTAB', 16), ('RCON', 16 * (P.rounds + 1)),
                       ('STATE', 16), ('TMP', 16), ('HEXOUT', 33)]:
        off[name] = cur
        cur += size
    # PACK (the obfuscated SPN body) goes last; its length needs the body.

    # ---- polymorphic opcode table ---------------------------------------- #
    rng = random.Random(seed ^ 0xA5A5A5A5)
    enc_vals = rng.sample(range(255), NUM_OPS)        # distinct, never 0xFF
    enc = {canonical: enc_vals[canonical] for canonical in range(NUM_OPS)}
    op_dec = [0xFF] * 256
    for canonical, byte in enc.items():
        op_dec[byte] = canonical

    # ---- SPN body (uses enc), then pack it (layer 2) --------------------- #
    body = build_spn_body(enc, off, P)
    off['PACK'] = cur
    pack_off = cur
    mem_size = cur + len(body)
    packed = bytes(b ^ k for b, k in zip(body, pack_keystream(len(body))))

    # ---- code at rest: UNPACK stub + zero region ------------------------- #
    code_off = 1 + OPERAND_LEN[UNPACK]                 # body lands right after
    unpack_stub = bytes([enc[UNPACK]]) + struct.pack('<HHH', pack_off, code_off,
                                                     len(body))
    assert len(unpack_stub) == code_off
    code_plain = unpack_stub + b'\x00' * len(body)

    # ---- data memory image ----------------------------------------------- #
    mem = bytearray(mem_size)
    mem[off['SBOX']:off['SBOX'] + 256] = bytes(P.sbox)
    mem[off['MUL2']:off['MUL2'] + 256] = bytes(P.mul[2])
    mem[off['MUL3']:off['MUL3'] + 256] = bytes(P.mul[3])
    mem[off['HEXTAB']:off['HEXTAB'] + 16] = b"0123456789abcdef"
    for r in range(P.rounds + 1):
        mem[off['RCON'] + 16 * r:off['RCON'] + 16 * r + 16] = P.rcon[r]
    mem[pack_off:pack_off + len(body)] = packed

    # ---- layer-1 rolling-XOR encryption + anti-tamper digest ------------- #
    enc_code = bytearray()
    k = XOR_KEY0
    for byte in code_plain:
        enc_code.append(byte ^ k)
        k = (k * 31 + 0x9E) & 0xFF
    digest = hashlib.sha256(bytes(code_plain) + bytes(mem)).digest()

    # ---- obfuscated opcode table + strings ------------------------------- #
    op_dec_obf = bytes(x ^ STR_XOR for x in op_dec)
    xs_err = bytes(x ^ STR_XOR for x in b"err\n")

    def arr(name, data):
        hexs = ','.join(f'0x{b:02x}' for b in data)
        return f"static const uint8_t {name}[{len(data)}] = {{{hexs}}};\n"

    hdr = Path(__file__).resolve().parent.parent / 'src' / 'vm_blob.h'
    hdr.write_text(
        "/* auto-generated by gen_vm.py - do not edit */\n"
        "#ifndef VM_BLOB_H\n#define VM_BLOB_H\n"
        "#include <stdint.h>\n"
        f"#define VM_CODE_SIZE {len(code_plain)}\n"
        f"#define VM_MEM_SIZE {mem_size}\n"
        f"#define SBOX_OFF {off['SBOX']}\n"
        f"#define UNPACK_SEED 0x{UNPACK_SEED:016x}ULL\n"
        + arr('vm_code_enc', enc_code)
        + arr('vm_code_sha', digest)
        + arr('vm_op_dec', op_dec_obf)
        + arr('vm_mem_init', mem)
        + arr('xs_err', xs_err)
        + "#endif\n"
    )
    print(f"[+] seed           : 0x{seed:x}")
    print(f"[+] rounds         : {P.rounds}")
    print(f"[+] spn body bytes : {len(body)}")
    print(f"[+] code size      : {len(code_plain)} (unpack stub {code_off} + body)")
    print(f"[+] mem size       : {mem_size} (pack @ {pack_off})")
    print(f"[+] wrote {hdr}")


def _parse_seed(argv) -> int:
    if len(argv) <= 1:
        return DEFAULT_SEED
    s = argv[1]
    return int(s, 16) if s.lower().startswith('0x') else int(s)


if __name__ == '__main__':
    gen(_parse_seed(sys.argv))
