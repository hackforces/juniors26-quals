"""Генерация scene.pcap — «снимок разговора с курьером» (Кривой человек).

Самодостаточный stdlib-builder реалистичного трафика:
  * Ethernet/ARP/IPv4/TCP/UDP с валидными чексуммами — Wireshark не помечает
    пакеты битыми;
  * полноценные TCP-сессии: SYN/SYN-ACK с опциями (MSS/SACK/WS), сквозные
    seq/ack, FIN-закрытие — Follow TCP Stream собирается;
  * фоновый шум: DNS, HTML/CSS/JSON «домашней панели» Бейкер-стрит, PNG с
    камеры, TLS-подобный bulk-поток, пара декой-POST на /watson-note;
  * ровно один POST /watson-note несёт message=<CTF_FLAG>.

Детерминировано от CTF_FLAG (seed = SHA-256), поэтому у одного инстанса
хэндаут стабилен между перезапусками. build() самопроверяется: флаг в файле
ровно один, размер >= 15 КБ.
"""

from __future__ import annotations

import calendar
import hashlib
import random
import re
import struct
from pathlib import Path

FLAG_RE = re.compile(rb"(?i)\b[a-z0-9_]{2,32}\{[^{}\s]{4,}\}")

CLIENT_IP, SERVER_IP, GW_IP = "10.42.0.7", "10.42.0.15", "10.42.0.1"
CLIENT_MAC, SERVER_MAC, GW_MAC = "024c5e104207", "029eb7104215", "02be71104201"
BASE_TS = calendar.timegm((2050, 6, 4, 3, 12, 0))  # глубокая ночь, UTC


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
    """Случайные байты без фигурных скобок — шум не должен матчить FLAG_RE."""
    return bytes(0x61 if b in (0x7B, 0x7D) else b for b in rng.randbytes(n))


class Capture:
    """pcap-контейнер + общий счётчик IP id и часы (микросекунды)."""

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
    """TCP-соединение: handshake с опциями, сквозные seq/ack, FIN-закрытие."""

    def __init__(self, cap: Capture, cport: int, sport: int, sip: str, dip: str, smac: str, dmac: str):
        self.cap = cap
        self.cip, self.sip, self.smac, self.dmac = sip, dip, smac, dmac
        self.cport, self.sport = cport, sport
        self.cseq = cap.rng.randrange(0x10000, 0x7FFF0000)
        self.sseq = cap.rng.randrange(0x10000, 0x7FFF0000)
        self.cwin = cap.rng.randrange(300, 900)   # после window scale
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
            sip, dip, smac, dmac = self.cip, self.sip, CLIENT_MAC, self.dmac
            sp, dp = self.cport, self.sport
        else:
            seq, ack, w = self.sseq, self.cseq, win or self.swin
            sip, dip, smac, dmac = self.sip, self.cip, self.smac, CLIENT_MAC
            sp, dp = self.sport, self.cport
        off = (20 + len(opts)) // 4
        tcp = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, off << 4, flags, w, 0, 0) + opts
        pseudo = _ip4(sip) + _ip4(dip) + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack("!H", _cksum(pseudo + tcp + payload)) + tcp[18:]
        _raw4(self.cap, sip, dip, 6, tcp + payload, smac, dmac)
        step = len(payload) + (1 if flags & 0x03 else 0)  # SYN/FIN занимают номер
        if from_client:
            self.cseq += step
        else:
            self.sseq += step

    def send(self, from_client: bool, data: bytes, mss: int = 1400) -> None:
        while data:
            chunk, data = data[:mss], data[mss:]
            self._seg(from_client, 0x18, chunk)        # PSH|ACK
            self._seg(not from_client, 0x10)           # ACK получателя

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


def dns_a(cap: Capture, rng: random.Random, name: str, addr: str) -> None:
    txid = rng.randrange(1, 0x10000)
    sport = rng.randrange(40000, 60000)
    query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + _name(name) + struct.pack("!HH", 1, 1)
    _udp(cap, query, sport, 53, CLIENT_IP, GW_IP, CLIENT_MAC, GW_MAC)
    resp = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + b"\xc0\x0c"
    resp += struct.pack("!HH", 1, 1)                       # хвост вопроса
    resp += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + _ip4(addr)  # ответ
    _udp(cap, resp, 53, sport, GW_IP, CLIENT_IP, GW_MAC, CLIENT_MAC)


def http_get(path: str, host: str, ua: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
        f"Accept: */*\r\nAccept-Language: en-GB,en;q=0.9\r\nConnection: keep-alive\r\n\r\n"
    ).encode()


def http_post(path: str, body: bytes, host: str, ua: str) -> bytes:
    head = (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode()
    return head + body


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


PANEL_HTML = (
    "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\">\n"
    "<title>Baker Street 221B — home panel</title>\n"
    "<link rel=\"stylesheet\" href=\"/panel.css\"></head>\n<body>\n"
    "<h1>Baker Street 221B — home panel</h1>\n<p class=\"stamp\">night watch, 03:14</p>\n<ul>\n"
    "<li>front door: locked (bolt and chain)</li>\n<li>study lamp: on</li>\n"
    "<li>kettle: off</li>\n<li>courier hatch: awaiting courier</li>\n"
    "<li>greenhouse heater: 16.2 C</li>\n</ul>\n<p>The latest courier note is delivered to the "
    "study terminal. Older notes are archived nightly, and unclaimed notes expire at dawn. "
    "If the study terminal is away, the panel keeps the note until an operator signs in.</p>\n"
    "<p class=\"foot\">panel 1.4 — Baker Street Automation, local only, no cloud</p>\n"
    "</body>\n</html>\n"
)

PANEL_CSS = (
    "body {\n  font-family: Georgia, serif;\n  margin: 2rem auto;\n  max-width: 42rem;\n"
    "  background: #f4efe6;\n  color: #2b2118;\n}\nh1 {\n  border-bottom: 2px solid #7a5c3e;\n"
    "}\nul {\n  list-style: square;\n}\n.stamp {\n  color: #7a5c3e;\n  font-style: italic;\n}\n"
    ".foot {\n  margin-top: 3rem;\n  font-size: 0.8rem;\n  color: #6b5d4d;\n}\n"
)

STATUS_JSON = (
    '{"uptime_s": 8451, "front_door": "locked", "kettle": "off", '
    '"hatch": "awaiting_courier", "greenhouse_c": 16.2, "last_motion": "study", "battery_pv": 87}'
)


def build(flag: str, root: Path) -> None:
    out = root / "download"
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(int.from_bytes(hashlib.sha256(("scene:" + flag).encode()).digest()[:8], "big"))
    cap = Capture(rng)
    next_port = rng.randrange(49152, 60000)

    def port() -> int:
        nonlocal next_port
        next_port = (next_port + rng.randrange(1, 4)) & 0xFFFF
        return next_port

    # подъём сети: ARP на панель + резолв baker.local
    arp(cap, 1, CLIENT_IP, CLIENT_MAC, SERVER_IP, "000000000000", "ffffffffffff")
    arp(cap, 2, SERVER_IP, SERVER_MAC, CLIENT_IP, CLIENT_MAC, CLIENT_MAC)
    dns_a(cap, rng, "baker.local", SERVER_IP)
    cap.pause(rng.uniform(1.0, 2.5))

    bot = "CourierBot/2.3"

    # фоновый поток 1: панель — HTML + стили + статус
    f = TcpFlow(cap, port(), 80, CLIENT_IP, SERVER_IP, SERVER_MAC, SERVER_MAC)
    f.send(True, http_get("/", "baker.local", bot))
    f.send(False, http_resp("baker-panel/1.4", "text/html; charset=utf-8", PANEL_HTML.encode()))
    f.send(True, http_get("/panel.css", "baker.local", bot))
    f.send(False, http_resp("baker-panel/1.4", "text/css", PANEL_CSS.encode()))
    f.send(True, http_get("/status.json", "baker.local", bot))
    f.send(False, http_resp("baker-panel/1.4", "application/json", STATUS_JSON.encode(), close=True))
    f.close()

    # фоновый поток 2: TLS-подобный bulk (телеметрия шлюза)
    cap.pause(rng.uniform(2.0, 5.0))
    t = TcpFlow(cap, port(), 443, CLIENT_IP, SERVER_IP, SERVER_MAC, SERVER_MAC)
    t.send(True, tls_block(rng, [(0x16, 236)]))                                # ClientHello
    t.send(False, tls_block(rng, [(0x16, 92), (0x16, 2404), (0x16, 0)]))       # SH + Cert + SHD
    t.send(True, tls_block(rng, [(0x16, 70), (0x14, 1), (0x16, 48)]))          # CKE + CCS + Fin
    t.send(False, tls_block(rng, [(0x14, 1), (0x16, 48)]))
    for _ in range(4):
        t.send(False, tls_block(rng, [(0x17, rng.randrange(1350, 1420))]))
    for _ in range(2):
        t.send(True, tls_block(rng, [(0x17, rng.randrange(700, 820))]))
    t.close()

    # фоновый поток 3: последний кадр с камеры
    cap.pause(rng.uniform(1.5, 4.0))
    png = b"\x89PNG\r\n\x1a\n" + noise(rng, 640)
    f = TcpFlow(cap, port(), 80, CLIENT_IP, SERVER_IP, SERVER_MAC, SERVER_MAC)
    f.send(True, http_get("/camera/last-frame.png", "baker.local", bot))
    f.send(False, http_resp("baker-panel/1.4", "image/png", png, close=True))
    f.close()

    # декой-заметки и целевая записка курьера
    for body, ua in (
        (b"message=remind+mrs+hudson+about+the+lamp", "curl/8.5.0"),
        (b"message=route+check+in+regents+park", "curl/8.5.0"),
        (b"message=" + flag.encode(), bot),
    ):
        cap.pause(rng.uniform(1.0, 3.0))
        f = TcpFlow(cap, port(), 80, CLIENT_IP, SERVER_IP, SERVER_MAC, SERVER_MAC)
        f.send(True, http_post("/watson-note", body, "baker.local", ua))
        f.send(False, http_resp("baker-panel/1.4", "text/plain", b"accepted\n", close=True))
        f.close()

    data = cap.write(out / "scene.pcap")

    # самопроверка: литерал флага в файле ровно один; флаг-подобные строки
    # допустимы только как части самого флага (личный флаг жюри может быть
    # составным — несколько {…}-групп, тогда широкий FLAG_RE матчит его
    # кусками). Посторонние кандидаты вне диапазона флага — ошибка: шум
    # генерится brace-free, и «второй флаг» игрока бы запутал.
    raw = flag.encode()
    occurrences = data.count(raw)
    if occurrences != 1:
        raise RuntimeError(
            f"scene.pcap self-check failed: flag literal occurs {occurrences}x"
        )
    span = (data.find(raw), data.find(raw) + len(raw))
    foreign = [
        m.group()
        for m in FLAG_RE.finditer(data)
        if m.start() < span[0] or m.end() > span[1]
    ]
    if foreign:
        raise RuntimeError(
            f"scene.pcap self-check failed: foreign flag-like strings: {foreign[:3]}"
        )
    if len(data) < 15000:
        raise RuntimeError(f"scene.pcap too small: {len(data)} bytes")


if __name__ == "__main__":
    import sys

    build("flag{selftest}", Path(sys.argv[1] if len(sys.argv) > 1 else "."))
    print("self-test: ok")
