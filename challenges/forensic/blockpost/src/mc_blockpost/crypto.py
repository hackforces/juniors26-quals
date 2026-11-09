"""Криптография протокола: AES-128/CFB8 (key = IV = shared secret), RSA-1024 + PKCS#1 v1.5.

Всё на чистом Python, чтобы генератор и солвер работали без зависимостей. Если установлен
пакет `cryptography`, AES-CFB8 считается через него (результат побайтно тот же, просто быстрее).
RSA-ключ генерируется детерминированно из seed, поэтому сборка pcap воспроизводима.
"""

import random

# ---------------------------------------------------------------------------
# AES-128 (только прямое преобразование: CFB8 и шифрует, и расшифровывает им)
# ---------------------------------------------------------------------------
def _xtime(a):
    a <<= 1
    return (a ^ 0x11B) if a & 0x100 else a


def _make_tables():
    # S-box через обратный элемент в GF(2^8) и аффинное преобразование
    exp, log = [0] * 512, [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x ^= _xtime(x)            # умножение на генератор 3
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    sbox = [0] * 256
    for a in range(256):
        inv = exp[255 - log[a]] if a else 0
        s = inv
        for k in range(1, 5):
            s ^= ((inv << k) | (inv >> (8 - k))) & 0xFF
        sbox[a] = s ^ 0x63
    te = [[0] * 256 for _ in range(4)]
    for a in range(256):
        s = sbox[a]
        s2 = _xtime(s)
        w = (s2 << 24) | (s << 16) | (s << 8) | (s2 ^ s)
        for r in range(4):
            te[r][a] = ((w >> (8 * r)) | (w << (32 - 8 * r))) & 0xFFFFFFFF
    return sbox, te


SBOX, (TE0, TE1, TE2, TE3) = _make_tables()


def _expand_key(key: bytes):
    assert len(key) == 16
    w = [int.from_bytes(key[i:i + 4], "big") for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = w[i - 1]
        if i % 4 == 0:
            t = ((t << 8) | (t >> 24)) & 0xFFFFFFFF
            t = (SBOX[t >> 24] << 24) | (SBOX[(t >> 16) & 0xFF] << 16) | \
                (SBOX[(t >> 8) & 0xFF] << 8) | SBOX[t & 0xFF]
            t ^= rcon << 24
            rcon = _xtime(rcon)
        w.append(w[i - 4] ^ t)
    return w


def _aes_encrypt_block(rk, block: bytes) -> bytes:
    s0 = int.from_bytes(block[0:4], "big") ^ rk[0]
    s1 = int.from_bytes(block[4:8], "big") ^ rk[1]
    s2 = int.from_bytes(block[8:12], "big") ^ rk[2]
    s3 = int.from_bytes(block[12:16], "big") ^ rk[3]
    for r in range(1, 10):
        k = 4 * r
        t0 = TE0[s0 >> 24] ^ TE1[(s1 >> 16) & 255] ^ TE2[(s2 >> 8) & 255] ^ TE3[s3 & 255] ^ rk[k]
        t1 = TE0[s1 >> 24] ^ TE1[(s2 >> 16) & 255] ^ TE2[(s3 >> 8) & 255] ^ TE3[s0 & 255] ^ rk[k + 1]
        t2 = TE0[s2 >> 24] ^ TE1[(s3 >> 16) & 255] ^ TE2[(s0 >> 8) & 255] ^ TE3[s1 & 255] ^ rk[k + 2]
        t3 = TE0[s3 >> 24] ^ TE1[(s0 >> 16) & 255] ^ TE2[(s1 >> 8) & 255] ^ TE3[s2 & 255] ^ rk[k + 3]
        s0, s1, s2, s3 = t0, t1, t2, t3
    out = bytearray(16)
    for i, (a, b, c, d) in enumerate(((s0, s1, s2, s3), (s1, s2, s3, s0),
                                      (s2, s3, s0, s1), (s3, s0, s1, s2))):
        x = ((SBOX[a >> 24] << 24) | (SBOX[(b >> 16) & 255] << 16) |
             (SBOX[(c >> 8) & 255] << 8) | SBOX[d & 255]) ^ rk[40 + i]
        out[4 * i:4 * i + 4] = x.to_bytes(4, "big")
    return bytes(out)


def aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    return _aes_encrypt_block(_expand_key(key), block)


class _PureCFB8:
    """AES/CFB8: на каждый байт — одно шифрование 16-байтного регистра сдвига."""

    def __init__(self, key: bytes, iv: bytes, decrypt: bool):
        self.rk = _expand_key(key)
        self.reg = bytearray(iv)
        self.decrypt = decrypt

    def update(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        reg, rk = self.reg, self.rk
        for i, b in enumerate(data):
            o = b ^ _aes_encrypt_block(rk, reg)[0]
            out[i] = o
            del reg[0]
            reg.append(b if self.decrypt else o)   # в регистр всегда идёт шифртекст
        return bytes(out)


def _fast_cfb8(key, iv, decrypt):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        try:
            from cryptography.hazmat.decrepit.ciphers.modes import CFB8 as mode
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.modes import CFB8 as mode
    except ImportError:
        return None
    c = Cipher(algorithms.AES(key), mode(iv))
    return c.decryptor() if decrypt else c.encryptor()


class CFB8:
    """Потоковый шифр одного направления соединения (состояние тянется между пакетами).

    В Minecraft key = IV = shared secret, отдельный экземпляр на каждое направление.
    """

    def __init__(self, key: bytes, iv: bytes = None, decrypt: bool = False, pure: bool = False):
        iv = key if iv is None else iv
        self._c = None if pure else _fast_cfb8(key, iv, decrypt)
        if self._c is None:
            self._c = _PureCFB8(key, iv, decrypt)

    def update(self, data: bytes) -> bytes:
        return self._c.update(data)


# ---------------------------------------------------------------------------
# RSA: детерминированная генерация, DER SubjectPublicKeyInfo, PKCS#1 v1.5
# ---------------------------------------------------------------------------
def _is_probable_prime(n: int, rng: random.Random, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        x = pow(rng.randrange(2, n - 2), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits: int, rng: random.Random) -> int:
    while True:
        n = rng.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _is_probable_prime(n, rng):
            return n


def generate_rsa(bits: int = 1024, seed: int = 0, e: int = 65537):
    """Возвращает (n, e, d). Детерминировано по seed."""
    rng = random.Random(seed)
    while True:
        p = _random_prime(bits // 2, rng)
        q = _random_prime(bits // 2, rng)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e and (p * q).bit_length() == bits:
            return p * q, e, pow(e, -1, phi)


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(v: int) -> bytes:
    b = v.to_bytes(v.bit_length() // 8 + 1, "big")   # ведущий 0, если старший бит = 1
    return _der(0x02, b)


RSA_ALG_ID = bytes.fromhex("300d06092a864886f70d0101010500")  # rsaEncryption, NULL


def rsa_public_der(n: int, e: int) -> bytes:
    """X.509 SubjectPublicKeyInfo (так сервер кладёт ключ в Encryption Request)."""
    rsa_pub = _der(0x30, _der_int(n) + _der_int(e))
    return _der(0x30, RSA_ALG_ID + _der(0x03, b"\x00" + rsa_pub))


def rsa_parse_public_der(der: bytes):
    """Обратный разбор SubjectPublicKeyInfo -> (n, e). Минимальный DER-парсер."""
    def read(buf, off):
        tag = buf[off]
        ln = buf[off + 1]
        off += 2
        if ln & 0x80:
            k = ln & 0x7F
            ln = int.from_bytes(buf[off:off + k], "big")
            off += k
        return tag, buf[off:off + ln], off + ln

    _, spki, _ = read(der, 0)
    _, _, off = read(spki, 0)                 # AlgorithmIdentifier
    _, bitstr, _ = read(spki, off)
    _, seq, _ = read(bitstr[1:], 0)
    _, n, off = read(seq, 0)
    _, e, _ = read(seq, off)
    return int.from_bytes(n, "big"), int.from_bytes(e, "big")


def rsa_pkcs1v15_encrypt(n: int, e: int, msg: bytes, rng: random.Random) -> bytes:
    k = (n.bit_length() + 7) // 8
    ps = bytes(rng.randrange(1, 256) for _ in range(k - 3 - len(msg)))
    em = b"\x00\x02" + ps + b"\x00" + msg
    return pow(int.from_bytes(em, "big"), e, n).to_bytes(k, "big")


def rsa_pkcs1v15_decrypt(n: int, d: int, ct: bytes) -> bytes:
    k = (n.bit_length() + 7) // 8
    em = pow(int.from_bytes(ct, "big"), d, n).to_bytes(k, "big")
    if em[:2] != b"\x00\x02":
        raise ValueError("bad PKCS#1 v1.5 padding")
    return em[em.index(b"\x00", 2) + 1:]


def minecraft_server_hash(server_id: bytes, shared_secret: bytes, public_der: bytes) -> str:
    """sha1 в "минекрафтовском" виде: знаковое big-endian число в hex, без ведущих нулей."""
    import hashlib
    h = int.from_bytes(hashlib.sha1(server_id + shared_secret + public_der).digest(),
                       "big", signed=True)
    return format(h, "x") if h >= 0 else "-" + format(-h, "x")
