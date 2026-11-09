#!/usr/bin/env python3
"""
Author disassembler for the mini-vm bytecode.

Unlike the old build, the program is hidden behind three obstacles, all of
which this tool undoes to demonstrate the intended reversing path:

  1. layer 1  - the code image is rolling-XOR encrypted;
  2. layer 2  - the real SPN body is NOT in the code image at all; a self-
                modifying UNPACK stub reconstructs it at run time from a
                splitmix64-obfuscated blob in data memory;
  3. polymorphic ISA - every build permutes the on-wire opcode bytes, so the
                opcode->mnemonic map must be read from the binary (vm_op_dec),
                not hardcoded.

For author convenience this reads the generated src/vm_blob.h (a participant
would instead carve the same arrays out of the stripped ELF).

Usage: python3 disasm_vm.py [path/to/vm_blob.h]
"""

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import gen_vm as G

NAMES = {
    G.NOP: "NOP", G.PUSH: "PUSH", G.POP: "POP", G.DUP: "DUP", G.SWAP: "SWAP",
    G.LOADIN: "LOADIN", G.LDB: "LDB", G.STB: "STB", G.ADD: "ADD", G.SUB: "SUB",
    G.XOR: "XOR", G.AND: "AND", G.SHL: "SHL", G.SHR: "SHR", G.EQ: "EQ",
    G.UNPACK: "UNPACK", G.PRINT: "PRINT", G.EXIT: "EXIT",
}


def read_blob(path: str):
    txt = Path(path).read_text()

    def arr(name):
        m = re.search(name + r"\[\d+\]\s*=\s*\{([^}]*)\}", txt)
        return bytes(int(x, 16) for x in m.group(1).split(","))

    def define(name):
        return int(re.search(rf"#define {name} (\w+)", txt).group(1), 0)

    return {
        "code_enc": arr("vm_code_enc"),
        "op_dec_obf": arr("vm_op_dec"),
        "mem": arr("vm_mem_init"),
        "code_size": define("VM_CODE_SIZE"),
    }


def rolling_xor(data: bytes) -> bytes:
    out = bytearray()
    k = 0x5A
    for b in data:
        out.append(b ^ k)
        k = (k * 31 + 0x9E) & 0xFF
    return bytes(out)


def decode(blob: bytes, op_dec):
    pc = 0
    while pc < len(blob):
        canonical = op_dec[blob[pc]]
        if canonical == 0xFF or canonical not in G.OPERAND_LEN:
            raise ValueError(f"invalid on-wire byte 0x{blob[pc]:02x} @ {pc}")
        n = G.OPERAND_LEN[canonical]
        yield pc, NAMES[canonical], blob[pc + 1:pc + 1 + n]
        pc += 1 + n


def fmt(off, name, oper):
    if name == "PUSH":
        return f"{off:04x}: PUSH 0x{struct.unpack('<Q', oper)[0]:x}"
    if name == "UNPACK":
        pk, co, ln = struct.unpack("<HHH", oper)
        return f"{off:04x}: UNPACK pack=0x{pk:x} code=0x{co:x} len={ln}"
    if name == "PRINT":
        a, b = struct.unpack("<HH", oper)
        return f"{off:04x}: PRINT 0x{a:x}, {b}"
    if oper:
        return f"{off:04x}: {name} {oper.hex()}"
    return f"{off:04x}: {name}"


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else str(
        Path(__file__).resolve().parent.parent / "src" / "vm_blob.h")
    b = read_blob(path)
    op_dec = bytes(x ^ 0x5A for x in b["op_dec_obf"])   # de-obfuscate the ISA map

    # layer 1 (only the UNPACK stub is real code here; the rest is zero filler)
    code = bytearray(rolling_xor(b["code_enc"]))
    pc0, nm0, op0 = next(iter(decode(bytes(code), op_dec)))
    assert nm0 == "UNPACK", f"expected UNPACK stub, got {nm0}"
    pk, co, ln = struct.unpack("<HHH", op0)
    print("; layer-1 image:")
    print(fmt(pc0, nm0, op0))
    print(f"; layer-2: reconstruct {ln} bytes at code+0x{co:x} from mem+0x{pk:x}")

    # layer 2: self-modifying unpack
    ks = G.pack_keystream(ln)
    body = bytes(b["mem"][pk + i] ^ ks[i] for i in range(ln))
    code[co:co + ln] = body

    # disassemble the reconstructed program
    print("; reconstructed SPN program:")
    count = 0
    for off, name, oper in decode(bytes(code[co:]), op_dec):
        print(fmt(off + co, name, oper))
        count += 1
        if name == "EXIT":
            break
    print(f"; {count} instructions")


if __name__ == "__main__":
    main()
