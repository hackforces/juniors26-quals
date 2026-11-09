"""Проверка pcap сторонними инструментами (опционально: scapy / tshark)."""

import os
import shutil
import subprocess
import tempfile
import unittest

from mc_blockpost.pcap import read_tcp_segments, reassemble, tcp_streams

from .util import cached_build

try:
    import scapy.all as scapy
except ImportError:  # pragma: no cover
    scapy = None

TSHARK = shutil.which("tshark")
MODES = [{}, dict(axis="z", lossy=True)]


class _PcapFile:
    def __init__(self, **mode):
        self.mode = mode

    def __enter__(self):
        fd, self.path = tempfile.mkstemp(suffix=".pcap")
        with os.fdopen(fd, "wb") as f:
            f.write(cached_build(**self.mode)["pcap"])
        return self.path

    def __exit__(self, *exc):
        os.unlink(self.path)


@unittest.skipUnless(scapy, "scapy не установлен")
class ScapyTest(unittest.TestCase):
    def test_checksums(self):
        for mode in MODES:
            with self.subTest(**mode), _PcapFile(**mode) as path:
                for p in scapy.rdpcap(path):
                    ip, tcp = p[scapy.IP], p[scapy.TCP]
                    got_ip, got_tcp = ip.chksum, tcp.chksum
                    del ip.chksum, tcp.chksum
                    fresh = scapy.Ether(bytes(p))
                    self.assertEqual(got_ip, fresh[scapy.IP].chksum)
                    self.assertEqual(got_tcp, fresh[scapy.TCP].chksum)


@unittest.skipUnless(TSHARK, "tshark не найден")
class TsharkTest(unittest.TestCase):
    def _tshark(self, *args):
        return subprocess.run([TSHARK, *args], capture_output=True, text=True,
                              check=True).stdout

    def test_checksums_valid(self):
        for mode in MODES:
            with self.subTest(**mode), _PcapFile(**mode) as path:
                bad = self._tshark("-r", path, "-o", "ip.check_checksum:TRUE",
                                   "-o", "tcp.check_checksum:TRUE",
                                   "-Y", "ip.checksum.status == 0 || tcp.checksum.status == 0")
                self.assertEqual(bad.strip(), "")

    def test_clean_capture_has_no_tcp_anomalies(self):
        with _PcapFile() as path:
            flags = self._tshark("-r", path, "-Y", "tcp.analysis.flags && !tcp.analysis.window_update")
            self.assertEqual(flags.strip(), "")
        with _PcapFile(axis="z", lossy=True) as path:
            flags = self._tshark("-r", path, "-Y", "tcp.analysis.retransmission")
            self.assertTrue(flags.strip())

    def test_follow_tcp_stream(self):
        for mode in MODES:
            with self.subTest(**mode), _PcapFile(**mode) as path:
                with open(path, "rb") as f:
                    segs = tcp_streams(read_tcp_segments(f.read()))
                for idx, cport in enumerate(sorted(segs)):
                    expected = reassemble(segs[cport])
                    out = self._tshark("-r", path, "-q", "-z", f"follow,tcp,raw,{idx}")
                    # строки с отступом — вторая сторона потока (сервер)
                    srv = "".join(l.strip() for l in out.splitlines() if l.startswith("\t"))
                    self.assertEqual(bytes.fromhex(srv), expected)


if __name__ == "__main__":
    unittest.main()
