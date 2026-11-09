#!/usr/bin/env python3
"""
spn.py - the custom 128-bit substitution-permutation network P used by mini-vm.

This is the single source of truth for the maths. Both the challenge generator
(gen_vm.py, which emits VM bytecode that computes P forward) and the author
solver (solve.py in the package root, which needs P^-1) import it. The deployed binary is a
*forward oracle* for P and contains no secret.

P is a keyless, public, invertible permutation on a 16-byte block:

    for r in range(R):
        state ^= RCON[r]          # AddRoundConstant
        state  = SBOX[state]      # SubBytes   (custom random S-box)
        state  = ShiftRows(state) # AES byte permutation (column-major)
        state  = MixColumns(state)# AES MDS matrix over GF(2^8), poly 0x11b
    state ^= RCON[R]              # final AddRoundConstant

Every step is invertible, so P is a bijection: a unique preimage always exists.
Diffusion (ShiftRows + MixColumns) makes every output byte depend on every input
byte within two rounds, so the key cannot be recovered one byte at a time.

The S-box and round constants are generated deterministically from a fixed seed,
so rebuilds are byte-identical. Pass a different seed to `build_params` for a
fresh instance.
"""

import random

BLOCK = 16
ROUNDS = 10
DEFAULT_SEED = 0x6D696E69766D2032  # "minivm 2" - fixed => reproducible build
GF_POLY = 0x11B


# --------------------------------------------------------------------------- #
# GF(2^8) arithmetic (AES field)
# --------------------------------------------------------------------------- #
def gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= (GF_POLY & 0xFF)
        b >>= 1
    return p


def _mul_table(k: int) -> list:
    return [gmul(x, k) for x in range(256)]


# --------------------------------------------------------------------------- #
# ShiftRows permutation (AES, column-major flat index i = row + 4*col)
# out[row + 4*col] = in[row + 4*((col + row) % 4)]
# --------------------------------------------------------------------------- #
def _shiftrows_src() -> list:
    src = [0] * 16
    for col in range(4):
        for row in range(4):
            src[row + 4 * col] = row + 4 * ((col + row) % 4)
    return src


SR_SRC = _shiftrows_src()
SR_SRC_INV = [SR_SRC.index(i) for i in range(16)]


class Params:
    """One concrete instance of P (S-box, GF tables, round constants)."""

    def __init__(self, seed: int = DEFAULT_SEED, rounds: int = ROUNDS):
        rng = random.Random(seed)
        self.rounds = rounds
        self.sbox = list(range(256))
        rng.shuffle(self.sbox)
        self.sbox_inv = [0] * 256
        for i, v in enumerate(self.sbox):
            self.sbox_inv[v] = i
        self.rcon = [bytes(rng.randrange(256) for _ in range(16))
                     for _ in range(rounds + 1)]
        self.mul = {k: _mul_table(k) for k in (2, 3, 9, 11, 13, 14)}

    # -- single steps ------------------------------------------------------- #
    def _mix_cols(self, s, m2, m3):
        o = [0] * 16
        for c in range(4):
            a, b, cc, d = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
            o[4 * c + 0] = m2[a] ^ m3[b] ^ cc ^ d
            o[4 * c + 1] = a ^ m2[b] ^ m3[cc] ^ d
            o[4 * c + 2] = a ^ b ^ m2[cc] ^ m3[d]
            o[4 * c + 3] = m3[a] ^ b ^ cc ^ m2[d]
        return o

    def _unmix_cols(self, s):
        m9, m11, m13, m14 = self.mul[9], self.mul[11], self.mul[13], self.mul[14]
        o = [0] * 16
        for c in range(4):
            a, b, cc, d = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
            o[4 * c + 0] = m14[a] ^ m11[b] ^ m13[cc] ^ m9[d]
            o[4 * c + 1] = m9[a] ^ m14[b] ^ m11[cc] ^ m13[d]
            o[4 * c + 2] = m13[a] ^ m9[b] ^ m14[cc] ^ m11[d]
            o[4 * c + 3] = m11[a] ^ m13[b] ^ m9[cc] ^ m14[d]
        return o

    # -- the permutation ---------------------------------------------------- #
    def forward(self, block: bytes) -> bytes:
        assert len(block) == BLOCK
        m2, m3 = self.mul[2], self.mul[3]
        s = list(block)
        for r in range(self.rounds):
            s = [s[i] ^ self.rcon[r][i] for i in range(16)]       # ARC
            s = [self.sbox[x] for x in s]                         # SubBytes
            s = [s[SR_SRC[i]] for i in range(16)]                 # ShiftRows
            s = self._mix_cols(s, m2, m3)                         # MixColumns
        s = [s[i] ^ self.rcon[self.rounds][i] for i in range(16)]  # final ARC
        return bytes(s)

    def inverse(self, block: bytes) -> bytes:
        assert len(block) == BLOCK
        s = [block[i] ^ self.rcon[self.rounds][i] for i in range(16)]
        for r in range(self.rounds - 1, -1, -1):
            s = self._unmix_cols(s)                               # InvMixColumns
            s = [s[SR_SRC_INV[i]] for i in range(16)]             # InvShiftRows
            s = [self.sbox_inv[x] for x in s]                     # InvSubBytes
            s = [s[i] ^ self.rcon[r][i] for i in range(16)]       # ARC
        return bytes(s)


def _selftest():
    import os
    p = Params()
    for _ in range(2000):
        x = os.urandom(16)
        assert p.inverse(p.forward(x)) == x
        assert p.forward(p.inverse(x)) == x
    # bijection sanity on the S-box
    assert sorted(p.sbox) == list(range(256))
    print("[+] spn.py self-test passed (forward/inverse round-trip, bijection)")


if __name__ == "__main__":
    _selftest()
