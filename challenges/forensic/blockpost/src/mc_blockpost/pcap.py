"""Минимальный writer/reader pcap (Ethernet/IPv4/TCP, корректные контрольные суммы).

Writer ведёт несколько TCP-соединений с правдоподобным поведением: трёхстороннее
рукопожатие, нарезка по MSS, отложенные ACK, закрытие через FIN, реальные таймстемпы.
"""

import random
import struct

from .protocol import SERVER_PORT

SRV_IP = "10.0.0.10"
CLI_IP = "10.0.0.50"
SRV_MAC = bytes.fromhex("525400a1b2c3")
CLI_MAC = bytes.fromhex("d85ed3112233")

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
MSS = 1460
WINDOW = 64240

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _ip_to_bytes(ip: str) -> bytes:
    return bytes(int(p) for p in ip.split("."))


class PcapWriter:
    """Набор кадров с таймстемпами. Часы `now` (секунды, float) двигает генератор."""

    def __init__(self, start_ts: float, seed: int = 0):
        self.records = []          # (ts, frame_bytes)
        self.now = start_ts
        self.rng = random.Random(seed)
        self.ip_id = {"c2s": self.rng.randrange(1 << 16), "s2c": self.rng.randrange(1 << 16)}

    def tick(self, lo: float, hi: float = None):
        self.now += lo if hi is None else self.rng.uniform(lo, hi)

    def stream(self, client_port: int) -> "TcpStream":
        return TcpStream(self, client_port)

    def frame(self, direction, sport, dport, seq, ack, flags, payload=b""):
        if direction == "c2s":
            src_ip, dst_ip, src_mac, dst_mac, ttl = CLI_IP, SRV_IP, CLI_MAC, SRV_MAC, 128
        else:
            src_ip, dst_ip, src_mac, dst_mac, ttl = SRV_IP, CLI_IP, SRV_MAC, CLI_MAC, 64

        # TCP header (data offset 5 -> 20 байт)
        tcp = struct.pack(">HHIIHHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                          (5 << 12) | flags, WINDOW, 0, 0)
        # псевдозаголовок для контрольной суммы TCP
        pseudo = _ip_to_bytes(src_ip) + _ip_to_bytes(dst_ip) + \
            struct.pack(">BBH", 0, 6, len(tcp) + len(payload))
        csum = _checksum(pseudo + tcp + payload)
        tcp = tcp[:16] + struct.pack(">H", csum) + tcp[18:] + payload

        ip_id = self.ip_id[direction]
        self.ip_id[direction] = (ip_id + 1) & 0xFFFF
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), ip_id, 0x4000,
                         ttl, 6, 0, _ip_to_bytes(src_ip), _ip_to_bytes(dst_ip))
        ip = ip[:10] + struct.pack(">H", _checksum(ip)) + ip[12:]

        self.records.append((self.now, dst_mac + src_mac + b"\x08\x00" + ip + tcp))
        self.now += self.rng.uniform(0.00002, 0.00012)   # сериализация на проводе
        return len(self.records) - 1

    def to_bytes(self) -> bytes:
        # global header: magic, v2.4, tz0, snaplen, linktype=1(Ethernet)
        out = [struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 262144, LINKTYPE_ETHERNET)]
        for ts, data in self.records:
            usec_total = round(ts * 1_000_000)
            sec, usec = divmod(usec_total, 1_000_000)
            out.append(struct.pack("<IIII", sec, usec, len(data), len(data)))
            out.append(data)
        return b"".join(out)

    def write(self, path):
        with open(path, "wb") as f:
            f.write(self.to_bytes())


class TcpStream:
    """Одно TCP-соединение клиент <-> сервер:25565."""

    def __init__(self, w: PcapWriter, client_port: int):
        self.w = w
        self.cport = client_port
        self.seq = {"c2s": w.rng.randrange(1 << 32), "s2c": w.rng.randrange(1 << 32)}
        self.unacked = {"c2s": 0, "s2c": 0}   # сегментов без ACK от другой стороны
        self.sent = []                       # (direction, seq, payload, record_index)

    def _ports(self, d):
        return (self.cport, SERVER_PORT) if d == "c2s" else (SERVER_PORT, self.cport)

    @staticmethod
    def _other(d):
        return "s2c" if d == "c2s" else "c2s"

    def _seg(self, d, flags, payload=b"", seq=None):
        sport, dport = self._ports(d)
        s = self.seq[d] if seq is None else seq
        ack = self.seq[self._other(d)] if flags & TCP_ACK else 0
        idx = self.w.frame(d, sport, dport, s, ack, flags, payload)
        if flags & TCP_ACK:
            self.unacked[self._other(d)] = 0   # ACK едет вместе с любым сегментом
        if seq is None:
            self.seq[d] = (s + len(payload) + (1 if flags & (TCP_SYN | TCP_FIN) else 0)) & 0xFFFFFFFF
        return s, idx

    def open(self, rtt=0.0006):
        self._seg("c2s", TCP_SYN)
        self.w.tick(rtt / 2)
        self._seg("s2c", TCP_SYN | TCP_ACK)
        self.w.tick(rtt / 2)
        self._seg("c2s", TCP_ACK)

    def ack(self, d):
        """Чистый ACK от стороны d (подтверждает всё, что пришло от другой стороны)."""
        self._seg(d, TCP_ACK)
        self.unacked[self._other(d)] = 0

    def send(self, d, data: bytes, mss: int = MSS, sizes=None):
        """Отправка данных: нарезка по MSS (или по заданным sizes), ACK каждые 2 сегмента."""
        off = 0
        while off < len(data):
            n = mss if sizes is None else next(sizes)
            part = data[off:off + n]
            off += len(part)
            last = off >= len(data)
            seq, idx = self._seg(d, TCP_ACK | (TCP_PSH if last else 0), part)
            self.sent.append((d, seq, part, idx))
            self.unacked[d] += 1
            if self.unacked[d] >= 2:          # delayed ACK: на каждый второй сегмент
                self.w.tick(0.00005, 0.0002)
                self.ack(self._other(d))

    def flush_acks(self, delay=0.04, sides=("c2s", "s2c")):
        """Отложенный ACK по таймеру для данных, пришедших от сторон sides."""
        for d in sides:
            if self.unacked[d]:
                self.w.tick(min(delay, 0.04))
                self.ack(self._other(d))

    def close(self, by="c2s"):
        other = self._other(by)
        self._seg(by, TCP_FIN | TCP_ACK)
        self.w.tick(0.0003)
        self._seg(other, TCP_FIN | TCP_ACK)
        self.w.tick(0.0003)
        self._seg(by, TCP_ACK)

    def retransmit(self, k):
        """Повтор k-го отправленного сегмента (тот же seq и payload, новый IP ID)."""
        d, seq, part, _ = self.sent[k]
        sport, dport = self._ports(d)
        self.w.frame(d, sport, dport, seq, self.seq[self._other(d)], TCP_ACK | TCP_PSH, part)


# ---------------------------------------------------------------------------
# Чтение
# ---------------------------------------------------------------------------
def read_tcp_segments(data: bytes):
    """Разбирает pcap (Ethernet/IPv4/TCP) -> список dict(src, sport, dst, dport, seq, flags, payload, ts)."""
    magic, = struct.unpack("<I", data[:4])
    if magic != PCAP_MAGIC:
        raise ValueError("не pcap (или другой byte order)")
    off = 24
    segs = []
    while off + 16 <= len(data):
        sec, usec, incl, _ = struct.unpack("<IIII", data[off:off + 16])
        off += 16
        frm = data[off:off + incl]
        off += incl
        if len(frm) < 14 + 20 + 20 or frm[12:14] != b"\x08\x00":
            continue
        ip_start = 14
        ihl = (frm[ip_start] & 0x0F) * 4
        if frm[ip_start + 9] != 6:
            continue
        total_len, = struct.unpack(">H", frm[ip_start + 2:ip_start + 4])
        tcp_start = ip_start + ihl
        src_port, dst_port, seq = struct.unpack(">HHI", frm[tcp_start:tcp_start + 8])
        data_off = (frm[tcp_start + 12] >> 4) * 4
        segs.append({
            "src": ".".join(map(str, frm[ip_start + 12:ip_start + 16])),
            "dst": ".".join(map(str, frm[ip_start + 16:ip_start + 20])),
            "sport": src_port, "dport": dst_port,
            "seq": seq, "flags": frm[tcp_start + 13],
            "payload": frm[tcp_start + data_off:ip_start + total_len],
            "ts": sec + usec / 1e6,
        })
    return segs


def tcp_streams(segs):
    """Группирует сегменты по соединениям: {(client_port): [seg, ...]} в порядке файла."""
    out = {}
    for s in segs:
        cport = s["dport"] if s["sport"] == SERVER_PORT else s["sport"]
        out.setdefault(cport, []).append(s)
    return out


def reassemble(segs, sport=SERVER_PORT) -> bytes:
    """Собирает поток данных одного соединения от порта sport по номерам последовательности.

    Порядок сегментов в файле значения не имеет: out-of-order раскладываются по seq,
    ретрансмиссии (уже покрытые байты) отбрасываются, перекрытия обрезаются.
    """
    mine = [s for s in segs if s["sport"] == sport]
    if not mine:
        return b""
    syn = [s for s in mine if s["flags"] & TCP_SYN]
    isn = (syn[0]["seq"] + 1) if syn else min(s["seq"] for s in mine if s["payload"])
    parts = sorted(((s["seq"] - isn) & 0xFFFFFFFF, s["payload"])
                   for s in mine if s["payload"])
    stream = bytearray()
    for rel, payload in parts:
        end = rel + len(payload)
        if end <= len(stream):
            continue                      # дубликат / ретрансмиссия
        if rel > len(stream):
            raise ValueError(f"дыра в потоке: ждали байт {len(stream)}, пришёл {rel}")
        stream += payload[len(stream) - rel:]
    return bytes(stream)
