#!/usr/bin/env python3
import argparse
import io
import json
import os
import re
import struct
import sys
import zipfile
import zlib
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.path.normpath(os.path.join(HERE, "..", "public"))

MC_PORT = 25565
# Packet IDs, protocol 777 (26.3)
LOGIN_ENC_REQUEST, LOGIN_ENC_RESPONSE = 0x01, 0x01        # clientbound / serverbound
LOGIN_SET_COMPRESSION, LOGIN_SUCCESS = 0x03, 0x02
CONFIG_FINISH = 0x03
PLAY_BLOCK_UPDATE = 0x08


# ---------- 1. pcap -> TCP-соединения ----------
def tcp_segments(raw):
    if struct.unpack("<I", raw[:4])[0] != 0xA1B2C3D4:
        sys.exit("[-] ожидается классический little-endian pcap")
    off = 24
    while off + 16 <= len(raw):
        incl = struct.unpack("<I", raw[off + 8:off + 12])[0]
        frm = raw[off + 16:off + 16 + incl]
        off += 16 + incl
        if frm[12:14] != b"\x08\x00" or frm[23] != 6:     # IPv4 / TCP
            continue
        ihl = (frm[14] & 0xF) * 4
        ip_len = struct.unpack(">H", frm[16:18])[0]
        t = 14 + ihl
        sport, dport, seq = struct.unpack(">HHI", frm[t:t + 8])
        doff = (frm[t + 12] >> 4) * 4
        yield sport, dport, seq, frm[t + 13], frm[t + doff:14 + ip_len]


def streams(raw):
    """{client_port: {"c2s": bytes, "s2c": bytes}}, каждое направление собрано по seq."""
    conns = {}
    for sport, dport, seq, flags, payload in tcp_segments(raw):
        cport, d = (dport, "s2c") if sport == MC_PORT else (sport, "c2s")
        c = conns.setdefault(cport, {"c2s": [None, []], "s2c": [None, []]})
        if flags & 0x02:                                  # SYN / SYN-ACK
            c[d][0] = (seq + 1) & 0xFFFFFFFF
        elif payload:
            c[d][1].append((seq, payload))
    out = {}
    for cport, c in conns.items():
        out[cport] = {}
        for d, (isn, parts) in c.items():
            buf = bytearray()
            for rel, p in sorted(((s - isn) & 0xFFFFFFFF, p) for s, p in parts):
                if rel + len(p) <= len(buf):
                    continue                              # ретрансмиссия
                if rel > len(buf):
                    sys.exit(f"[-] дыра в TCP-потоке :{cport} {d}")
                buf += p[len(buf) - rel:]
            out[cport][d] = bytes(buf)
    return out


# ---------- 2. кадры протокола ----------
def varint(buf, off):
    val = shift = 0
    while True:
        b = buf[off]
        off += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return (val - (1 << 32) if val & (1 << 31) else val), off
        shift += 7
        if shift >= 35:
            raise ValueError("VarInt too big")


def prefixed(buf, off):
    n, off = varint(buf, off)
    return buf[off:off + n], off + n


def frames(stream, threshold=None):
    """(id, data, end) подряд; threshold — порог компрессии (None = без неё)."""
    off = 0
    while off < len(stream):
        length, o = varint(stream, off)
        body = stream[o:o + length]
        if len(body) < length:
            return
        off = o + length
        if threshold is not None:
            dlen, k = varint(body, 0)
            body = zlib.decompress(body[k:]) if dlen else body[k:]
        pid, k = varint(body, 0)
        yield pid, body[k:], off


# ---------- 3. AES/CFB8 ----------
def cfb8_decryptor(key):
    """key = IV = shared secret; один непрерывный поток на направление."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        cfb8 = None
        for _mod in ("cryptography.hazmat.primitives.ciphers.modes",
                     "cryptography.hazmat.decrepit.ciphers.modes"):
            try:
                cand = __import__(_mod, fromlist=["CFB8"]).CFB8
            except ImportError:
                continue
            if isinstance(cand(key), modes.Mode):
                cfb8 = cand
                break
        if cfb8 is not None:
            return Cipher(algorithms.AES(key), cfb8(key)).decryptor().update
    except Exception:
        pass
    try:
        from Crypto.Cipher import AES
        return AES.new(key, AES.MODE_CFB, iv=key, segment_size=8).decrypt
    except ImportError:
        pass
    enc = _aes128(key)
    reg = bytearray(key)

    def update(data):
        out = bytearray()
        for b in data:
            out.append(b ^ enc(bytes(reg))[0])
            del reg[0]
            reg.append(b)
        return bytes(out)
    return update


def _aes128(key):
    """Прямое AES-128 на чистом Python (только для резервного пути)."""
    def xt(a):
        a <<= 1
        return a ^ 0x11B if a & 0x100 else a
    sbox, p, q = [0] * 256, 1, 1
    while True:                                           # классическая генерация S-box
        p = p ^ xt(p)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ (q << 1 | q >> 7) ^ (q << 2 | q >> 6) ^ (q << 3 | q >> 5) ^ (q << 4 | q >> 4)
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    rk = list(key)
    rcon = 1
    while len(rk) < 176:
        t = rk[-4:]
        if len(rk) % 16 == 0:
            t = [sbox[t[1]] ^ rcon, sbox[t[2]], sbox[t[3]], sbox[t[0]]]
            rcon = xt(rcon)
        rk += [rk[-16 + i] ^ t[i] for i in range(4)]

    def enc(block):
        s = [b ^ k for b, k in zip(block, rk[:16])]
        for r in range(1, 11):
            s = [sbox[b] for b in s]
            s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]          # ShiftRows
            if r < 10:
                m = []
                for c in range(4):
                    a = s[4 * c:4 * c + 4]
                    t = a[0] ^ a[1] ^ a[2] ^ a[3]
                    m += [a[i] ^ t ^ xt(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
                s = m
            s = [b ^ k for b, k in zip(s, rk[16 * r:16 * r + 16])]
        return bytes(s)
    return enc


# ---------- 4. позиция и шрифт ----------
def position(b):
    v = int.from_bytes(b, "big")
    x, z, y = v >> 38, (v >> 12) & 0x3FFFFFF, v & 0xFFF
    x -= (x >> 25) << 26
    z -= (z >> 25) << 26
    y -= (y >> 11) << 12
    return x, y, z


FONT = {
    "A": ".###.#...#######...##...#", "B": "####.#...#####.#...#####.",
    "C": ".#####....#....#.....####", "D": "####.#...##...##...#####.",
    "E": "######....####.#....#####", "F": "######....####.#....#....",
    "G": ".#####....#..###...#.####", "H": "#...##...#######...##...#",
    "I": "#####..#....#....#..#####", "J": "..###...#....#.#..#..##..",
    "K": "#...##..#.###..#..#.#...#", "L": "#....#....#....#....#####",
    "M": "#...###.###.#.##...##...#", "N": "#...###..##.#.##..###...#",
    "O": ".###.#...##...##...#.###.", "P": "####.#...#####.#....#....",
    "Q": ".###.#...##.#.##..#..##.#", "R": "####.#...#####.#..#.#...#",
    "S": ".#####.....###.....#####.", "T": "#####..#....#....#....#..",
    "U": "#...##...##...##...#.###.", "V": "#...##...##...#.#.#...#..",
    "W": "#...##...##.#.###.###...#", "X": "#...#.#.#...#...#.#.#...#",
    "Y": "#...#.#.#...#....#....#..", "Z": "#####...#...#...#...#####",
    "0": ".###.#..###.#.###..#.###.", "1": "..#...##....#....#...###.",
    "2": ".###.#...#..##..#...#####", "3": "####.....#.###.....#####.",
    "4": "#..#.#..#.#####...#....#.", "5": "######....####.....#####.",
    "6": ".###.#....####.#...#.###.", "7": "#####....#...#...#....#..",
    "8": ".###.#...#.###.#...#.###.", "9": ".###.#...#.####....#.###.",
    "_": "....................#####", "{": "..##...#...##....#....##.",
    "}": ".##....#....##...#...##..",
}
GLYPH = {v: k for k, v in FONT.items()}
W, STEP = 5, 6


def read_wall(blocks):
    # самая населённая плоскость x=const или z=const — это стена
    planes = Counter()
    for x, _, z, _ in blocks:
        planes["z", z] += 1
        planes["x", x] += 1
    (axis, val), _ = planes.most_common(1)[0]
    wall = [((x if axis == "z" else z), y, s) for x, y, z, s in blocks
            if (z if axis == "z" else x) == val]
    fg = Counter(s for *_, s in wall).most_common(1)[0][0]
    pts = {(h, y) for h, y, s in wall if s == fg}
    hs, ys = [p[0] for p in pts], [p[1] for p in pts]
    width, top = max(hs) - min(hs) + 1, max(ys)

    best = None
    for mirror in (False, True):                          # с какой стороны стоит зритель
        rows = [["."] * width for _ in range(top - min(ys) + 1)]
        for h, y in pts:
            rows[top - y][(max(hs) - h) if mirror else (h - min(hs))] = "#"
        for shift in range(STEP):                         # пустые левые столбцы 1-го глифа
            text = ""
            for gi in range((width + shift + STEP - 1) // STEP):
                cell = "".join(rows[r][c] if 0 <= c < width else "."
                               for r in range(5)
                               for c in range(gi * STEP - shift, gi * STEP - shift + W))
                text += GLYPH.get(cell, "?")
            key = (text.count("?"), shift, mirror)
            if best is None or key < best[0]:
                best = (key, rows, text, axis, val, fg, len(pts))
    return best[1:]


# ---------- 5. решение ----------
def load(args):
    if len(args) == 1 and zipfile.is_zipfile(args[0]):
        z = zipfile.ZipFile(args[0])
        name = {os.path.basename(n): n for n in z.namelist()}
        return z.read(name["challenge.pcap"]), z.read(name["latest.log"]).decode()
    pcap, log = args if args else (os.path.join(PUBLIC, "challenge.pcap"),
                                   os.path.join(PUBLIC, "latest.log"))
    with open(pcap, "rb") as f, open(log, encoding="utf-8") as g:
        return f.read(), g.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*", help="challenge.pcap latest.log | blockpost.zip")
    ap.add_argument("--expect", help="ожидаемый флаг (проверка сборки)")
    args = ap.parse_args()
    raw, log = load(args.files)

    # --- негативные проверки: флага нет в открытом виде ---
    for name, blob in (("pcap", raw), ("log", log.encode())):
        assert not re.search(rb"(?i)ctf\{", blob), f"флаг виден в {name} как строка!"

    # --- соединения: status ping (открыт) и login (шифрованный) ---
    conns = streams(raw)
    login = None
    for cport, c in sorted(conns.items()):
        pid, data, _ = next(frames(c["c2s"]))
        proto, o = varint(data, 0)
        host, o = prefixed(data, o)
        intent, _ = varint(data, o + 2)
        print(f"[+] :{cport} handshake protocol={proto} host={host.decode()} intent={intent}")
        if intent == 1:
            status = json.loads(prefixed(next(frames(c["s2c"]))[1], 0)[0])
            print(f"    status: {status['version']}, players: "
                  f"{[p['name'] for p in status['players'].get('sample', [])]}")
        elif intent == 2:
            login = c
    assert login, "нет login-соединения"

    # --- открытая часть логина ---
    for pid, data, s2c_off in frames(login["s2c"]):
        if pid == LOGIN_ENC_REQUEST:
            sid, o = prefixed(data, 0)
            pub, o = prefixed(data, o)
            token, o = prefixed(data, o)
            break
    for pid, data, c2s_off in frames(login["c2s"]):
        if pid == LOGIN_ENC_RESPONSE:
            break
    print(f"[+] Encryption Request: key {len(pub)} B DER, verify token {token.hex()}")

    # --- секрет из лога по verify token ---
    sessions = re.findall(r"verify_token=([0-9a-f]+).*?secret=([0-9a-f]{32})", log, re.S)
    print(f"[+] в latest.log сессий с шифрованием: {len(sessions)}")
    secret = bytes.fromhex(dict(sessions)[token.hex()])
    print(f"[+] shared secret: {secret.hex()}")

    s2c = cfb8_decryptor(secret)(login["s2c"][s2c_off:])
    blocks, state, thr = [], "login", None
    off = 0
    while off < len(s2c):                                 # login -> configuration -> play
        try:
            pid, data, end = next(frames(s2c[off:], thr))
        except StopIteration:
            break
        off += end
        if state == "login" and pid == LOGIN_SET_COMPRESSION:
            thr = varint(data, 0)[0]
        elif state == "login" and pid == LOGIN_SUCCESS:
            state = "configuration"
        elif state == "configuration" and pid == CONFIG_FINISH:
            state = "play"
        elif state == "play" and pid == PLAY_BLOCK_UPDATE:
            x, y, z = position(data[:8])
            blocks.append((x, y, z, varint(data, 8)[0]))
    print(f"[+] порог компрессии {thr}, block_update в play: {len(blocks)}")

    rows, text, axis, val, fg, n = read_wall(blocks)
    print(f"[+] стена: {axis}={val}, block-state {fg}, {n} блоков\n")
    print("\n".join("".join(r) for r in rows))
    flag = text.lower()
    print(f"\n[+] надпись: {text}\n[+] флаг:   {flag}")

    # --- честность ---
    assert "?" not in text, "надпись не прочиталась целиком"
    assert re.fullmatch(r"(?:innoctf|ctf)\{[0-9a-z_]+\}", flag), "неожиданный формат флага"
    # без расшифровки поток после Encryption Request — мусор
    assert next(frames(login["s2c"][s2c_off:]), (None,))[0] != LOGIN_SET_COMPRESSION
    # подходит ровно один секрет из лога; остальные не дают Set Compression
    ok = []
    for _, sec in sessions:
        pt = cfb8_decryptor(bytes.fromhex(sec))(login["s2c"][s2c_off:s2c_off + 8])
        try:
            if next(frames(pt))[0] == LOGIN_SET_COMPRESSION:
                ok.append(sec)
        except (StopIteration, IndexError, ValueError):
            pass
    assert ok == [secret.hex()] or len(set(ok)) == 1, f"секрет неоднозначен: {ok}"
    # ложные следы: несколько типов блоков и вторая населённая плоскость
    assert len(Counter(s for *_, s in blocks)) > 2
    planes = Counter(z for _, _, z, _ in blocks) + Counter(x for x, _, _, _ in blocks)
    assert len([p for p, c in planes.items() if c >= 20]) >= 2, "нет ложной плоскости"

    if args.expect is not None and flag != args.expect.lower():
        sys.exit(f"[-] ожидали {args.expect}, получили {flag}")
    print("[+] OK")
    return flag


if __name__ == "__main__":
    main()
