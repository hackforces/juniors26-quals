"""Генерация quarters.pcap — «ночной прогон экспериментального полигона HQ»
(Три четверти и один).

Самодостаточный stdlib-builder реалистичного трафика — по образцу генераторов
«Кривого человека» и «Серебряного клинка»:
  * Ethernet/ARP/IPv4/TCP/UDP/ICMP с валидными чексуммами — Wireshark не
    помечает пакеты битыми;
  * полноценные TCP-сессии (SYN/опции/seq/ack/FIN — Follow TCP Stream
    работает), UDP/DNS с настоящими ответами (вопрос в ответе сжат
    указателем 0xC00C), NTP-обмены, ICMP-пинги, mDNS-мультикаст,
    broadcast-системный лог;
  * фоновый шум: статус-страница коллектора (HTML/CSS), TLS-подобные
    аплинки архива, десятки декой-DNS, телеметрия датчиков;
  * паззл — передача HQ: управляющие датаграммы `HQ/CASE/<id>` и
    `HQ/SPEC/v1;...` плюс шарды `HQ/<seq>/<slot>/` (3 блока данных +
    XOR-чётность, base64, маска sha256(case:seq:slot)[0], в каждой группе
    отсутствует блок seq mod 3). Порядок шардов перемешан сидом от case-id.

Детерминировано от CTF_FLAG (seed = SHA-256); build() самопроверяется:
передача восстанавливается во флаг ровно один раз, размер в пределах
100–250 КБ.
"""

from __future__ import annotations

import base64
import calendar
import hashlib
import random
import re
import struct
from pathlib import Path

SENSOR_IP, COLL_IP = "203.0.113.1", "203.0.113.2"
CLIENT_IP, GW_IP = "203.0.113.23", "203.0.113.254"
UPLINK_IP = "198.51.100.70"
SENSOR_MAC, COLL_MAC = "02c900710001", "02c900710002"
CLIENT_MAC, GW_MAC = "02c900710023", "02c90071fe01"
HQ_SPORT, HQ_DPORT = 41000, 41001
BASE_TS = calendar.timegm((2050, 3, 14, 8, 17, 0))  # утренний прогон, UTC


def _cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _ip4(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def _same_subnet(ip: str) -> bool:
    return ip.startswith("203.0.113.")


def _name(name: str) -> bytes:
    return b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"


def noise(rng: random.Random, n: int) -> bytes:
    """Случайные байты без фигурных скобок."""
    return bytes(0x5B if b in (0x7B, 0x7D) else b for b in rng.randbytes(n))


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


def _route(dip: str) -> tuple[str, str]:
    """MAC назначения: свой сегмент — хост, иначе шлюз."""
    if _same_subnet(dip):
        return {SENSOR_IP: SENSOR_MAC, COLL_IP: COLL_MAC, CLIENT_IP: CLIENT_MAC,
                GW_IP: GW_MAC}.get(dip, GW_MAC)
    return GW_MAC


def _raw4(cap: Capture, sip: str, dip: str, proto: int, payload: bytes,
          smac: str, dmac: str | None = None, df: bool = True) -> None:
    flags = 0x4000 if df else 0
    dmac = dmac or _route(dip)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), cap.ip_id,
                      flags, 64, proto, 0, _ip4(sip), _ip4(dip))
    hdr = hdr[:10] + struct.pack("!H", _cksum(hdr)) + hdr[12:]
    cap.emit(_eth(dmac, smac, 0x0800, hdr + payload))


class TcpFlow:
    """TCP-соединение: handshake, сквозные seq/ack, FIN."""

    def __init__(self, cap: Capture, cip: str, cport: int, dip: str, sport: int):
        self.cap = cap
        self.cip, self.sip = cip, dip
        self.smac, self.dmac = _route(dip), _route(dip)
        if dip == UPLINK_IP:
            self.dmac = GW_MAC  # за пределами полигона — через шлюз
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

    def _seg(self, from_client: bool, flags: int, payload: bytes = b"",
             opts: bytes = b"", win: int | None = None) -> None:
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


def _udp(cap: Capture, payload: bytes, sport: int, dport: int, sip: str, dip: str,
         smac: str, dmac: str | None = None) -> None:
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = _ip4(sip) + _ip4(dip) + struct.pack("!BBH", 0, 17, 8 + len(payload))
    hdr = hdr[:6] + struct.pack("!H", _cksum(pseudo + hdr + payload)) + hdr[8:]
    _raw4(cap, sip, dip, 17, hdr + payload, smac, dmac, df=False)


def arp(cap: Capture, oper: int, spa: str, sha: str, tpa: str, tha: str, dmac: str) -> None:
    payload = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, oper)
               + bytes.fromhex(sha) + _ip4(spa) + bytes.fromhex(tha) + _ip4(tpa))
    cap.emit(_eth(dmac, sha, 0x0806, payload), gap=0.0003)


def dns_exchange(cap: Capture, rng: random.Random, name: str, qtype: int,
                 answers: list, rcode: int = 0, who: str = CLIENT_IP) -> None:
    """Запрос + ответ резолвера (вопрос в ответе сжат 0xC00C)."""
    txid = rng.randrange(1, 0x10000)
    sport = rng.randrange(40000, 60000)
    query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + _name(name) + struct.pack("!HH", qtype, 1)
    _udp(cap, query, sport, 53, who, GW_IP, CLIENT_MAC if who == CLIENT_IP else COLL_MAC)
    an = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", t, 1, ttl, len(rd)) + rd
                  for t, ttl, rd in answers)
    resp = struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, len(answers), 0, 0)
    resp += b"\xc0\x0c" + struct.pack("!HH", qtype, 1) + an
    _udp(cap, resp, 53, sport, GW_IP, who, GW_MAC,
         CLIENT_MAC if who == CLIENT_IP else COLL_MAC)


def a_rec(addr: str, ttl: int = 300) -> tuple:
    return (1, ttl, _ip4(addr))


def icmp_ping(cap: Capture, rng: random.Random, dip: str, who: str = CLIENT_IP) -> None:
    body = noise(rng, 32)
    ident = rng.randrange(1, 0x10000)
    smac = CLIENT_MAC if who == CLIENT_IP else COLL_MAC
    for typ in (8, 0):
        icmp = struct.pack("!BBHIH", typ, 0, 0, ident, 1) + body
        icmp = icmp[:2] + struct.pack("!H", _cksum(icmp)) + icmp[4:]
        if typ == 8:
            _raw4(cap, who, dip, 1, icmp, smac)
        else:
            _raw4(cap, dip, who, 1, icmp, _route(who))


def ntp_exchange(cap: Capture, rng: random.Random) -> None:
    for tx in (0x1B, 0x24):  # client -> server -> client
        body = struct.pack("!BBBb", tx, 2, 6, -23) + noise(rng, 44)
        if tx == 0x1B:
            _udp(cap, body, rng.randrange(40000, 60000), 123, CLIENT_IP, GW_IP, CLIENT_MAC)
        else:
            _udp(cap, body, 123, 40000, GW_IP, CLIENT_IP, GW_MAC, CLIENT_MAC)


def mdns_announce(cap: Capture, rng: random.Random, name: str, addr: str) -> None:
    """Мультикаст mDNS: PTR/A анонс коллектора."""
    answers = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 4500, 4) + _ip4(addr)
    msg = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + _name(name) + struct.pack("!HH", 12, 1) + answers
    _udp(cap, msg, 5353, 5353, COLL_IP, "224.0.0.251", COLL_MAC, "01005e0000fb")


SYSLOG_FACILITIES = (
    "range-daemon: channel calibration ok, drift 0.{r} Hz",
    "sensor09: antenna polarization {a}, snr {s} dB",
    "collector: ring buffer {p}% used, dropping none",
    "range-master: schedule slot {n} acknowledged by 2 of 3 stations",
    "meteo: gusts {g} m/s, visibility good, range clear",
)


def syslog_broadcast(cap: Capture, rng: random.Random) -> None:
    line = SYSLOG_FACILITIES[rng.randrange(len(SYSLOG_FACILITIES))].format(
        r=rng.randrange(10, 99), a=rng.choice(["vertical", "horizontal", "circular"]),
        s=rng.randrange(11, 38), p=rng.randrange(7, 64), n=rng.randrange(1, 48),
        g=rng.randrange(2, 14),
    ).encode()
    _udp(cap, b"<30>" + line, 514, 514, SENSOR_IP, "203.0.113.255", SENSOR_MAC,
         "ffffffffffff")


def http_get(path: str, host: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"User-Agent: hq-console/0.9 (range terminal)\r\n"
        f"Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\nConnection: keep-alive\r\n\r\n"
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


STATUS_HTML = (
    "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\">\n"
    "<title>HQ collector — range status</title>\n"
    "<link rel=\"stylesheet\" href=\"/assets/panel.css\"></head>\n<body>\n"
    "<h1>HQ collector 03</h1>\n<p class=\"tag\">experimental range · uplink pool B</p>\n"
    "<table>\n<tr><th>sensor</th><th>last frame</th><th>rssi</th></tr>\n"
    "<tr><td>sensor09</td><td>telemetry/temperature/17</td><td>-61 dBm</td></tr>\n"
    "<tr><td>sensor11</td><td>telemetry/tide/04</td><td>-58 dBm</td></tr>\n"
    "<tr><td>sensor12</td><td>telemetry/voltage/88</td><td>-70 dBm</td></tr>\n"
    "</table>\n<p>Datagrams with malformed routing are quarantined, not dropped: "
    "the range is licensed to lose individual shards. Reconstruction is the "
    "operator's problem.</p>\n"
    "<p class=\"foot\">collector engine 0.9 — HQ range ops</p>\n</body>\n</html>\n"
)

STATUS_CSS = (
    "body {\n  font-family: 'Iowan Old Style', serif;\n  margin: 2rem auto;\n"
    "  max-width: 42rem;\n  background: #eef1ee;\n  color: #1d2a24;\n}\n"
    "h1 {\n  letter-spacing: 0.05em;\n}\n.tag {\n  color: #4c6b58;\n"
    "  font-style: italic;\n}\ntable {\n  border-collapse: collapse;\n}\n"
    "th, td {\n  border: 1px solid #c8d2ca;\n  padding: 0.25rem 0.6rem;\n}\n"
    ".foot {\n  margin-top: 2.4rem;\n  font-size: 0.8rem;\n}\n"
)

TELEMETRY = (
    "telemetry/temperature/17", "telemetry/tide/04", "telemetry/voltage/88",
    "telemetry/humidity/31", "telemetry/gyro/09", "telemetry/battery/62",
    "telemetry/pressure/45", "telemetry/heading/21",
)

DNS_POOL = [
    ("collector.lab", 1, [a_rec(COLL_IP)]),
    ("sensor09.lab", 1, [a_rec(SENSOR_IP)]),
    ("time.lab", 1, [a_rec(GW_IP)]),
    ("archive.lab", 1, [a_rec(UPLINK_IP)]),
    ("www.collector.lab", 1, []),
    ("collector.lab", 28, []),
    ("collector.lab", 15, [(15, 3600, struct.pack("!H", 10) + _name("relay.lab"))]),
    ("status.collector.lab", 16, [(16, 600, bytes([22]) + b"range-B pool nightly sync")]),
    ("2.113.0.203.in-addr.arpa", 12, [(12, 3600, _name("collector.lab"))]),
    ("ghost.lab", 1, [], 3),
    ("mqtt.sensor09.lab", 1, [], 3),
]


def _mask(case_id: str, sequence: int, slot: str) -> int:
    return hashlib.sha256(f"{case_id}:{sequence}:{slot}".encode()).digest()[0]


def _xor3(*parts: bytes) -> bytes:
    return bytes(a ^ b ^ c for a, b, c in zip(*parts))


def hq_payloads(flag: str) -> tuple[str, list[bytes]]:
    """Управляющие датаграммы + перемешанные шарды передачи HQ."""
    raw = flag.encode()
    case_id = hashlib.sha256(raw).hexdigest()[:12]
    width = 4
    stripe_size = width * 3
    stripes = [raw[i:i + stripe_size].ljust(stripe_size, b"\0")
               for i in range(0, len(raw), stripe_size)]
    payloads = [
        f"HQ/CASE/{case_id}".encode(),
        b"HQ/SPEC/v1;data=3;parity=xor;encoding=base64;key=sha256(case:seq:slot)[0];missing=seq-mod-3",
    ]
    for sequence, stripe in enumerate(stripes):
        shards = [stripe[i:i + width] for i in range(0, stripe_size, width)]
        parity = _xor3(shards[0], shards[1], shards[2])
        missing = sequence % 3
        for slot, plain in enumerate(shards):
            if slot == missing:
                continue
            encrypted = bytes(v ^ _mask(case_id, sequence, str(slot)) for v in plain)
            payloads.append(f"HQ/{sequence:03d}/{slot}/".encode() + base64.b64encode(encrypted))
        encrypted_parity = bytes(v ^ _mask(case_id, sequence, "P") for v in parity)
        payloads.append(f"HQ/{sequence:03d}/P/".encode() + base64.b64encode(encrypted_parity))
    random.Random(int(case_id, 16)).shuffle(payloads[2:])
    return case_id, payloads


def build(flag: str, root: Path) -> None:
    out = root / "download"
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(int.from_bytes(hashlib.sha256(("hq:" + flag).encode()).digest()[:8], "big"))
    cap = Capture(rng)
    next_port = rng.randrange(49152, 60000)

    def port() -> int:
        nonlocal next_port
        next_port = (next_port + rng.randrange(1, 4)) & 0xFFFF
        return next_port

    case_id, hq = hq_payloads(flag)

    # подъём полигона: гратуитозный ARP шлюза, резолв пары sensor->collector
    arp(cap, 1, GW_IP, GW_MAC, "0.0.0.0", "000000000000", "ffffffffffff")
    arp(cap, 2, GW_IP, GW_MAC, CLIENT_IP, CLIENT_MAC, CLIENT_MAC)
    arp(cap, 1, SENSOR_IP, SENSOR_MAC, COLL_IP, "000000000000", "ffffffffffff")
    arp(cap, 2, COLL_IP, COLL_MAC, SENSOR_IP, SENSOR_MAC, SENSOR_MAC)
    dns_exchange(cap, rng, "collector.lab", 1, [a_rec(COLL_IP)], who=SENSOR_IP)
    cap.pause(rng.uniform(1.0, 2.5))

    # статус-страница коллектора
    f = TcpFlow(cap, CLIENT_IP, port(), COLL_IP, 80)
    f.send(True, http_get("/status", "collector.lab"))
    f.send(False, http_resp("collector-engine/0.9", "text/html; charset=utf-8", STATUS_HTML.encode()))
    f.send(True, http_get("/assets/panel.css", "collector.lab"))
    f.send(False, http_resp("collector-engine/0.9", "text/css", STATUS_CSS.encode(), close=True))
    f.close()

    # основной прогон: фон полигона, внутри — окна передачи HQ
    dns_pool = list(DNS_POOL)
    rng.shuffle(dns_pool)
    hq_queue = list(hq)
    hq_next = rng.uniform(3.0, 6.0)     # первая датаграмма HQ
    hq_gap = rng.uniform(0.15, 0.5)     # темп передачи
    uplinks = [
        (COLL_IP, "archive sync", 26),
        (CLIENT_IP, "console dashboard", 9),
        (COLL_IP, "archive sync", 22),
    ]
    uplink_wait = rng.uniform(20.0, 40.0)
    while hq_queue or dns_pool or uplinks:
        # фоновые события
        roll = rng.random()
        if roll < 0.34 and dns_pool:
            name, qtype, answers, *rc = dns_pool.pop(0)
            dns_exchange(cap, rng, name, qtype, answers, rcode=rc[0] if rc else 0,
                         who=rng.choice([CLIENT_IP, COLL_IP]))
        elif roll < 0.46:
            arp(cap, 1, rng.choice([CLIENT_IP, SENSOR_IP]),
                rng.choice([CLIENT_MAC, SENSOR_MAC]), COLL_IP, "000000000000",
                "ffffffffffff")
            arp(cap, 2, COLL_IP, COLL_MAC, SENSOR_IP, SENSOR_MAC, SENSOR_MAC)
        elif roll < 0.56:
            icmp_ping(cap, rng, rng.choice([COLL_IP, GW_IP, SENSOR_IP]),
                      who=rng.choice([CLIENT_IP, COLL_IP]))
        elif roll < 0.63:
            ntp_exchange(cap, rng)
        elif roll < 0.71:
            syslog_broadcast(cap, rng)
        elif roll < 0.77:
            mdns_announce(cap, rng, "collector.lab", COLL_IP)
        elif roll < 0.93:
            _udp(cap, rng.choice(TELEMETRY).encode(), HQ_SPORT, HQ_DPORT,
                 SENSOR_IP, COLL_IP, SENSOR_MAC, COLL_MAC)
        elif uplinks:
            src, what, records = uplinks.pop(0)
            t = TcpFlow(cap, src, port(), UPLINK_IP, 443)
            t.send(True, tls_block(rng, [(0x16, rng.randrange(180, 260))]))
            t.send(False, tls_block(rng, [(0x16, 96), (0x16, rng.randrange(1400, 2600)), (0x16, 0)]))
            t.send(True, tls_block(rng, [(0x16, 64), (0x14, 1), (0x16, 48)]))
            t.send(False, tls_block(rng, [(0x14, 1), (0x16, 48)]))
            for _ in range(records):
                t.send(False, tls_block(rng, [(0x17, rng.randrange(1300, 1420))]))
            for _ in range(rng.randrange(2, 5)):
                t.send(True, tls_block(rng, [(0x17, rng.randrange(200, 900))]))
            t.close()
            cap.pause(uplink_wait)
        else:
            _udp(cap, rng.choice(TELEMETRY).encode(), HQ_SPORT, HQ_DPORT,
                 SENSOR_IP, COLL_IP, SENSOR_MAC, COLL_MAC)
        cap.pause(rng.uniform(0.05, 0.4))

        # окно HQ: датаграммы передачи вперемешку с фоном
        hq_next -= 1
        while hq_next <= 0 and hq_queue:
            _udp(cap, hq_queue.pop(0), HQ_SPORT, HQ_DPORT, SENSOR_IP, COLL_IP,
                 SENSOR_MAC, COLL_MAC)
            hq_next = hq_gap
            hq_gap = rng.uniform(0.1, 0.6)
            cap.pause(rng.uniform(0.0, 0.12))

    dns_exchange(cap, rng, "collector.lab", 1, [a_rec(COLL_IP, ttl=60)])

    data = cap.write(out / "quarters.pcap")

    # самопроверка: солверная логика восстанавливает флаг ровно один раз
    found = re.search(rb"HQ/CASE/([0-9a-f]{12})", data)
    if not found or found.group(1).decode() != case_id:
        raise RuntimeError("quarters.pcap self-check failed: CASE header lost")
    groups: dict[int, dict[str, bytes]] = {}
    for match in re.finditer(rb"HQ/(\d{3})/([012P])/([A-Za-z0-9+/=]+)", data):
        sequence = int(match.group(1))
        slot = match.group(2).decode()
        encrypted = base64.b64decode(match.group(3))
        groups.setdefault(sequence, {})[slot] = bytes(
            v ^ _mask(case_id, sequence, slot) for v in encrypted
        )
    result = bytearray()
    for sequence, shards in sorted(groups.items()):
        missing = str(sequence % 3)
        known = [shards[str(s)] for s in range(3) if str(s) != missing]
        shards[missing] = bytes(a ^ b ^ c for a, b, c in zip(shards["P"], known[0], known[1]))
        result.extend(b"".join(shards[str(s)] for s in range(3)))
    if result.rstrip(b"\0") != flag.encode():
        raise RuntimeError(f"quarters.pcap self-check failed: {bytes(result[:64])!r}")
    if not 100_000 <= len(data) <= 250_000:
        raise RuntimeError(f"quarters.pcap size out of range: {len(data)} bytes")


if __name__ == "__main__":
    import sys

    build("CTF{quarters_selftest}", Path(sys.argv[1] if len(sys.argv) > 1 else "."))
    print("self-test: ok")
