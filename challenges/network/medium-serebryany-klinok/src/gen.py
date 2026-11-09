"""Генерация night.pcap — «ночные обращения к городскому справочнику»
(Серебряный клинок).

Самодостаточный stdlib-builder реалистичного трафика:
  * Ethernet/ARP/IPv4/TCP/UDP/ICMP с валидными чексуммами — Wireshark не
    помечает пакеты битыми;
  * полноценные TCP-сессии (SYN/опции/seq/ack/FIN — Follow TCP Stream
    работает), UDP/DNS с настоящими ответами, вопрос в ответах сжат
    указателем 0xC00C, как в реальном DNS;
  * фоновый шум: HTTP-портал справочника (HTML/CSS), TLS-подобный аплинк,
    ICMP-пинг, десяток декой-DNS (A/AAAA/MX/TXT/PTR/NXDOMAIN);
  * экзофильтрация: серия запросов `<nn>-<base32>.silver.baker`, где
    склеенные метки (без префикса nn-) дают Base32 флага; ответы на них —
    NXDOMAIN (данные в самих запросах).

Детерминировано от CTF_FLAG (seed = SHA-256); build() самопроверяется:
метки восстанавливаются в флаг ровно один раз, размер >= 15 КБ.
"""

from __future__ import annotations

import calendar
import hashlib
import random
import re
import struct
from pathlib import Path

LABEL_RE = re.compile(rb"[\x00-\x3f](\d\d-[a-z2-7]+)\x06silver\x05baker")

CLIENT_IP, GW_IP = "10.66.0.23", "10.66.0.1"
DIR_IP, UPLINK_IP = "198.51.100.70", "203.0.113.9"
CLIENT_MAC, GW_MAC = "02660a660023", "02be71106601"
BASE_TS = calendar.timegm((2050, 6, 4, 2, 31, 0))  # ночь, UTC


def _cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _ip4(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def _name(name: str) -> bytes:
    return b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"


def noise(rng: random.Random, n: int) -> bytes:
    """Случайные байты без фигурных скобок."""
    return bytes(0x61 if b in (0x7B, 0x7D) else b for b in rng.randbytes(n))


class Capture:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.ip_id = rng.randrange(0x8000, 0xC000)
        self.t = float(BASE_TS) + rng.uniform(0.0, 1.0)
        self.records: list[tuple[float, bytes]] = []

    def emit(self, frame: bytes, gap: float | None = None) -> None:
        self.ip_id = (self.ip_id + 1) & 0xFFFF
        self.t += self.rng.uniform(0.004, 0.045) if gap is None else gap
        self.records.append((self.t, frame))

    def pause(self, seconds: float) -> None:
        self.t += seconds

    def write(self, path: Path) -> bytes:
        out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        for ts, frame in self.records:
            usec = int(round(ts * 1_000_000))
            sec, usec = divmod(usec, 1_000_000)
            out += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
        path.write_bytes(out)
        return out


def _eth(dst: str, src: str, ethertype: int, payload: bytes) -> bytes:
    return bytes.fromhex(dst) + bytes.fromhex(src) + struct.pack("!H", ethertype) + payload


def _raw4(cap: Capture, sip: str, dip: str, proto: int, payload: bytes, smac: str, dmac: str, df: bool = True) -> None:
    flags = 0x4000 if df else 0
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), cap.ip_id, flags, 64, proto, 0, _ip4(sip), _ip4(dip))
    hdr = hdr[:10] + struct.pack("!H", _cksum(hdr)) + hdr[12:]
    cap.emit(_eth(dmac, smac, 0x0800, hdr + payload))


class TcpFlow:
    """TCP-соединение через шлюз: handshake, сквозные seq/ack, FIN."""

    def __init__(self, cap: Capture, cport: int, sport: int, dip: str):
        self.cap = cap
        self.cip, self.sip, self.smac, self.dmac = CLIENT_IP, dip, CLIENT_MAC, GW_MAC
        self.cport, self.sport = cport, sport
        self.cseq = cap.rng.randrange(0x10000, 0x7FFF0000)
        self.sseq = cap.rng.randrange(0x10000, 0x7FFF0000)
        self.cwin = cap.rng.randrange(300, 900)
        self.swin = cap.rng.randrange(80, 600)
        opts = (
            struct.pack("!BBH", 2, 4, 1460)      # MSS
            + struct.pack("!BB", 4, 2)           # SACK permitted
            + b"\x01\x01"                        # NOP NOP
            + struct.pack("!BBB", 3, 3, 7)       # Window scale
            + b"\x01"                            # NOP (выравнивание до 12 байт)
        )
        self._seg(True, 0x02, b"", opts, win=64240)
        self._seg(False, 0x12, b"", opts, win=64240)
        self._seg(True, 0x10)

    def _seg(self, from_client: bool, flags: int, payload: bytes = b"", opts: bytes = b"", win: int | None = None) -> None:
        if from_client:
            seq, ack, w = self.cseq, self.sseq, win or self.cwin
            sip, dip, smac, dmac = self.cip, self.sip, self.smac, self.dmac
            sp, dp = self.cport, self.sport
        else:
            seq, ack, w = self.sseq, self.cseq, win or self.swin
            sip, dip, smac, dmac = self.sip, self.cip, self.dmac, self.smac
            sp, dp = self.sport, self.cport
        off = (20 + len(opts)) // 4
        tcp = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, off << 4, flags, w, 0, 0) + opts
        pseudo = _ip4(sip) + _ip4(dip) + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack("!H", _cksum(pseudo + tcp + payload)) + tcp[18:]
        _raw4(self.cap, sip, dip, 6, tcp + payload, smac, dmac)
        step = len(payload) + (1 if flags & 0x03 else 0)
        if from_client:
            self.cseq += step
        else:
            self.sseq += step

    def send(self, from_client: bool, data: bytes, mss: int = 1400) -> None:
        while data:
            chunk, data = data[:mss], data[mss:]
            self._seg(from_client, 0x18, chunk)
            self._seg(not from_client, 0x10)

    def close(self) -> None:
        self._seg(True, 0x11)
        self._seg(False, 0x10)
        self._seg(False, 0x11)
        self._seg(True, 0x10)


def _udp(cap: Capture, payload: bytes, sport: int, dport: int, sip: str, dip: str, smac: str, dmac: str) -> None:
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = _ip4(sip) + _ip4(dip) + struct.pack("!BBH", 0, 17, 8 + len(payload))
    hdr = hdr[:6] + struct.pack("!H", _cksum(pseudo + hdr + payload)) + hdr[8:]
    _raw4(cap, sip, dip, 17, hdr + payload, smac, dmac, df=False)


def arp(cap: Capture, oper: int, spa: str, sha: str, tpa: str, tha: str, dmac: str) -> None:
    payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, oper) + bytes.fromhex(sha) + _ip4(spa) + bytes.fromhex(tha) + _ip4(tpa)
    cap.emit(_eth(dmac, sha, 0x0806, payload), gap=0.0003)


def dns_exchange(cap: Capture, rng: random.Random, name: str, qtype: int, answers: list, rcode: int = 0) -> None:
    """Запрос с клиента + ответ резолвера (вопрос в ответе сжат 0xC00C)."""
    txid = rng.randrange(1, 0x10000)
    sport = rng.randrange(40000, 60000)
    query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + _name(name) + struct.pack("!HH", qtype, 1)
    _udp(cap, query, sport, 53, CLIENT_IP, GW_IP, CLIENT_MAC, GW_MAC)
    an = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", t, 1, ttl, len(rd)) + rd for t, ttl, rd in answers)
    resp = struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, len(answers), 0, 0)
    resp += b"\xc0\x0c" + struct.pack("!HH", qtype, 1) + an
    _udp(cap, resp, 53, sport, GW_IP, CLIENT_IP, GW_MAC, CLIENT_MAC)


def a_rec(addr: str, ttl: int = 300) -> tuple:
    return (1, ttl, _ip4(addr))


def http_get(path: str, host: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0\r\n"
        f"Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\nAccept-Language: en-GB,en;q=0.5\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode()


def http_resp(server: str, ctype: str, body: bytes, close: bool = False) -> bytes:
    conn = "close" if close else "keep-alive"
    return (
        f"HTTP/1.1 200 OK\r\nServer: {server}\r\nContent-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: {conn}\r\n\r\n"
    ).encode() + body


def tls_block(rng: random.Random, blocks: list[tuple[int, int]]) -> bytes:
    out = b""
    for ctype, size in blocks:
        ver = b"\x03\x01" if ctype == 0x16 else b"\x03\x03"
        out += bytes([ctype]) + ver + struct.pack("!H", size) + noise(rng, size)
    return out


DIRECTORY_HTML = (
    "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\">\n"
    "<title>Baker City Directory — night desk</title>\n"
    "<link rel=\"stylesheet\" href=\"/assets/app.css\"></head>\n<body>\n"
    "<h1>Baker City Directory</h1>\n<p class=\"tag\">night desk · unrestricted index</p>\n"
    "<form action=\"/directory\" method=\"get\">\n  <input name=\"q\" value=\"wharf\">\n"
    "  <button>search</button>\n</form>\n<h2>Results for “wharf”, night=1</h2>\n<ol>\n"
    "<li>Primrose Wharf — coal, tide tables, night watchman: J. Cobb</li>\n"
    "<li>Old Gravel Wharf — closed after the barge year; records moved to annex</li>\n"
    "<li>Harbourmaster office — opens 06:00, ring twice</li>\n"
    "<li>Silver Yard (private) — access by written order only</li>\n</ol>\n"
    "<p>Night queries are logged for the constable rounds. Unmatched names are kept "
    "for seven days in the reserve index, then handed to the city archive.</p>\n"
    "<p class=\"foot\">directory engine 3.1 — Baker City Records Office</p>\n"
    "</body>\n</html>\n"
)

DIRECTORY_CSS = (
    "body {\n  font-family: 'Iowan Old Style', serif;\n  margin: 2rem auto;\n"
    "  max-width: 44rem;\n  background: #eef0ee;\n  color: #1f2a24;\n}\n"
    "h1 {\n  letter-spacing: 0.04em;\n}\n.tag {\n  color: #4c6b58;\n"
    "  font-style: italic;\n}\nol li {\n  margin: 0.4rem 0;\n}\nform input {\n"
    "  padding: 0.3rem 0.6rem;\n}\n.foot {\n  margin-top: 3rem;\n  font-size: 0.8rem;\n}\n"
)


def build(flag: str, root: Path) -> None:
    out = root / "download"
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(int.from_bytes(hashlib.sha256(("night:" + flag).encode()).digest()[:8], "big"))
    cap = Capture(rng)
    next_port = rng.randrange(49152, 60000)

    def port() -> int:
        nonlocal next_port
        next_port = (next_port + rng.randrange(1, 4)) & 0xFFFF
        return next_port

    # подъём сети
    arp(cap, 1, CLIENT_IP, CLIENT_MAC, GW_IP, "000000000000", "ffffffffffff")
    arp(cap, 2, GW_IP, GW_MAC, CLIENT_IP, CLIENT_MAC, CLIENT_MAC)
    dns_exchange(cap, rng, "baker.city", 1, [a_rec(DIR_IP)])
    cap.pause(rng.uniform(2.0, 5.0))

    # вечерний визит на портал справочника
    f = TcpFlow(cap, port(), 80, DIR_IP)
    f.send(True, http_get("/directory?q=wharf&night=1", "baker.city"))
    f.send(False, http_resp("directory-engine/3.1", "text/html; charset=utf-8", DIRECTORY_HTML.encode()))
    f.send(True, http_get("/assets/app.css", "baker.city"))
    f.send(False, http_resp("directory-engine/3.1", "text/css", DIRECTORY_CSS.encode(), close=True))
    f.close()

    # ночная серия: декой-запросы вперемешку с экзофильтрацией silver.baker
    text = base32_lower(flag)
    chunks = [text[i : i + 30] for i in range(0, len(text), 30)]
    pool = [
        ("www.baker.city", 1, [], 0),                                    # AAAA — пусто
        ("patrol-report.silver.baker", 1, [a_rec(UPLINK_IP)], 0),        # декой в зоне silver
        ("baker.city", 15, [(15, 3600, struct.pack("!H", 10) + _name("mail.baker.city"))], 0),       # MX
        ("verify.baker.city", 16, [(16, 600, bytes([28]) + b"city-directory nightly index")], 0),    # TXT
        ("70.100.51.198.in-addr.arpa", 12, [(12, 3600, _name("baker.city"))], 0),                    # PTR
        ("duty-log.silver.baker", 1, [], 3),                             # NXDOMAIN-декой
        ("ntp.baker.city", 1, [a_rec(GW_IP)], 0),
        ("ghost.baker.city", 1, [], 3),
    ]
    events, ci = [], 0
    while ci < len(chunks) or pool:
        for _ in range(2):
            if pool:
                events.append(pool.pop(0))
        if ci < len(chunks):
            events.append((f"{ci:02d}-{chunks[ci]}.silver.baker", 1, [], 3))  # NXDOMAIN
            ci += 1

    for name, qtype, answers, rcode in events:
        dns_exchange(cap, rng, name, qtype, answers, rcode=rcode)
        cap.pause(rng.uniform(12.0, 55.0))

    # контроль связи + ночной аплинк
    icmp_ping(cap, rng, DIR_IP)
    cap.pause(rng.uniform(20.0, 60.0))
    t = TcpFlow(cap, port(), 443, UPLINK_IP)
    t.send(True, tls_block(rng, [(0x16, 236)]))
    t.send(False, tls_block(rng, [(0x16, 92), (0x16, 2102), (0x16, 0)]))
    t.send(True, tls_block(rng, [(0x16, 70), (0x14, 1), (0x16, 48)]))
    t.send(False, tls_block(rng, [(0x14, 1), (0x16, 48)]))
    for _ in range(4):
        t.send(False, tls_block(rng, [(0x17, rng.randrange(1300, 1420))]))
    for _ in range(2):
        t.send(True, tls_block(rng, [(0x17, rng.randrange(600, 780))]))
    t.close()

    dns_exchange(cap, rng, "www.baker.city", 1, [a_rec(DIR_IP, ttl=60)])

    data = cap.write(out / "night.pcap")

    # самопроверка: солверная логика восстанавливает флаг ровно один раз
    labels, seen = [], set()
    for lab in LABEL_RE.findall(data):
        if lab not in seen:
            seen.add(lab)
            labels.append(lab.split(b"-", 1)[1])
    import base64 as _b64

    s = b"".join(labels).upper()
    recovered = _b64.b32decode(s + b"=" * (-len(s) % 8))
    if recovered != flag.encode():
        raise RuntimeError(f"night.pcap self-check failed: {recovered!r}")
    if len(data) < 15000:
        raise RuntimeError(f"night.pcap too small: {len(data)} bytes")


def base32_lower(flag: str) -> str:
    import base64

    return base64.b32encode(flag.encode()).decode().rstrip("=").lower()


def icmp_ping(cap: Capture, rng: random.Random, dip: str) -> None:
    body = noise(rng, 32)
    ident = rng.randrange(1, 0x10000)
    for typ in (8, 0):
        icmp = struct.pack("!BBHIH", typ, 0, 0, ident, 1) + body
        icmp = icmp[:2] + struct.pack("!H", _cksum(icmp)) + icmp[4:]
        if typ == 8:
            _raw4(cap, CLIENT_IP, dip, 1, icmp, CLIENT_MAC, GW_MAC)
        else:
            _raw4(cap, dip, CLIENT_IP, 1, icmp, GW_MAC, CLIENT_MAC)


if __name__ == "__main__":
    import sys

    build("flag{selftest}", Path(sys.argv[1] if len(sys.argv) > 1 else "."))
    print("self-test: ok")
