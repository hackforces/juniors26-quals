import itertools
import re
import unittest
import zipfile
import io

from mc_blockpost.generator import DEFAULT_FLAG, FG_STATE, build, make_zip
from mc_blockpost.pcap import read_tcp_segments, tcp_streams
from mc_blockpost.protocol import ID, unframe
from mc_blockpost.solver import (
    block_updates, compression_threshold, connections, find_secret, log_secrets,
    login_handshake, looks_decrypted, placements, solve_bytes,
)

from .util import cached_build, run_author_solver

FLAGS = [
    DEFAULT_FLAG,
    "FLAG{M1NECRAFT_BL0CKS}",
    "ctf{a}",                                    # короткий, кончается на '}'
    "ctf{the_quick_brown_fox_jumps_over_lazy_dog_0123456789}",
    "{NOPE_IS_A_DECOY}",                         # первый глиф с пустыми левыми столбцами
]
MODES = [dict(axis=a, lossy=l) for a, l in itertools.product(("x", "z"), (False, True))]


class RoundTripTest(unittest.TestCase):
    def test_flags(self):
        for flag in FLAGS:
            with self.subTest(flag=flag):
                res = cached_build(flag)
                self.assertEqual(solve_bytes(res["pcap"], res["log"])["text"], flag.upper())

    def test_all_hard_mode_combinations(self):
        for mode in MODES:
            with self.subTest(**mode):
                res = cached_build(**mode)
                self.assertEqual(solve_bytes(res["pcap"], res["log"])["text"],
                                 DEFAULT_FLAG.upper())

    def test_author_solver(self):
        for flag, mode in [(DEFAULT_FLAG, {}), ("InnoCTF{a}", {}),
                           (None, dict(axis="z", lossy=True))]:
            with self.subTest(flag=flag, **mode):
                res = cached_build(flag, **mode)
                p = run_author_solver(res, flag or DEFAULT_FLAG)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertIn("[+] OK", p.stdout)

    def test_deterministic(self):
        a, b = build(), build()
        self.assertEqual(a["pcap"], b["pcap"])
        self.assertEqual(a["log"], b["log"])
        self.assertEqual(make_zip([("x", b"1")]), make_zip([("x", b"1")]))

    def test_flag_not_in_plaintext(self):
        for mode in MODES:
            res = cached_build(**mode)
            self.assertNotIn(b"ctf{", res["pcap"].lower())
            self.assertNotIn("ctf{", res["log"].lower())
            z = make_zip([("challenge.pcap", res["pcap"]), ("latest.log", res["log"].encode())])
            with zipfile.ZipFile(io.BytesIO(z)) as zf:
                self.assertEqual(sorted(zf.namelist()),
                                 ["blockpost/challenge.pcap", "blockpost/latest.log"])

    def test_bad_input(self):
        with self.assertRaises(ValueError):
            build("ctf{no spaces}")
        with self.assertRaises(ValueError):       # короче ложной надписи — отказ
            build("}}}")


class RealisticSessionTest(unittest.TestCase):
    """Сессия устроена как настоящая online-mode: всё, что после Encryption Response, — шифртекст."""

    @classmethod
    def setUpClass(cls):
        cls.res = cached_build()
        cls.conns = connections(cls.res["pcap"])
        cls.login = [c for c in cls.conns if c["intent"] == 2][0]
        cls.hs = login_handshake(cls.login)

    def test_two_connections_status_then_login(self):
        self.assertEqual([c["intent"] for c in self.conns], [1, 2])
        self.assertTrue(all(c["protocol"] == 777 for c in self.conns))
        self.assertIn(b'"protocol":777', self.conns[0]["s2c"])

    def test_encryption_request(self):
        self.assertEqual(self.hs["server_id"], b"")
        self.assertEqual(len(self.hs["public_key"]), 162)
        self.assertEqual(len(self.hs["verify_token"]), 4)
        self.assertTrue(self.hs["should_authenticate"])
        self.assertEqual(self.hs["verify_token"], self.res["verify_token"])

    def test_ciphertext_without_key_is_garbage(self):
        ct = self.login["s2c"][self.hs["s2c_enc_off"]:]
        self.assertFalse(looks_decrypted(ct))
        self.assertEqual(block_updates(ct), [])

    def test_exactly_one_log_secret_fits(self):
        cands = log_secrets(self.res["log"])
        self.assertEqual(len(cands), 4)
        ct = self.login["s2c"][self.hs["s2c_enc_off"]:self.hs["s2c_enc_off"] + 64]
        from mc_blockpost.crypto import CFB8
        fits = [sec for _, sec in cands if looks_decrypted(CFB8(sec, decrypt=True).update(ct))]
        self.assertEqual(fits, [self.res["secret"]])
        self.assertEqual(find_secret(self.login, self.hs, self.res["log"]), self.res["secret"])
        # 2-я и 3-я сессии к 10.0.0.10 — один и тот же ключ сервера: различает только verify token
        fps = re.findall(r"fp=sha1:([0-9a-f]+)", self.res["log"])
        self.assertEqual(fps[1], fps[2])
        self.assertNotEqual(fps[2], fps[3])

    def test_both_routes_agree(self):
        r = solve_bytes(self.res["pcap"], self.res["log"])
        thr = compression_threshold(r["s2c"])
        self.assertEqual(thr, 256)
        fg = {(x, y, z) for x, y, z, s in r["blocks"] if s == FG_STATE}
        self.assertEqual(sorted(placements(r["c2s"], thr)), sorted(fg))

    def test_decoys_present(self):
        blocks = solve_bytes(self.res["pcap"], self.res["log"])["blocks"]
        self.assertGreater(len({s for *_, s in blocks}), 3)
        # NOPE — ложная надпись лаймовой шерстью (state 2099); шумовые блоки на той же
        # плоскости не считаем, иначе счётчик зависит от длины флага.
        self.assertEqual(sum(1 for _, _, z, s in blocks if z == 72 and s == 2099), 53)


class HardModeTest(unittest.TestCase):
    def test_lossy_needs_real_reassembly(self):
        res = cached_build(lossy=True)
        segs = tcp_streams(read_tcp_segments(res["pcap"]))[51036]
        s2c = [s for s in segs if s["sport"] == 25565 and s["payload"]]
        seqs = [s["seq"] for s in s2c]
        self.assertNotEqual(seqs, sorted(seqs))               # out-of-order
        self.assertGreater(len(seqs), len(set(seqs)))         # ретрансмиссии
        ts = [s["ts"] for s in segs]
        self.assertEqual(ts, sorted(ts))                      # время в файле монотонно

    def test_axis_z_wall_orientation(self):
        # геометрия стены калибрована под «боевую» длину флага (26 симв.):
        # собираем синтетический флаг той же длины, не храня литерал в репозитории
        probe = "innoctf{" + "x" * 17 + "}"
        res = cached_build(probe, axis="z")
        blocks = solve_bytes(res["pcap"], res["log"])["blocks"]
        fg = [(x, y, z) for x, y, z, s in blocks if s == FG_STATE]
        self.assertEqual({x for x, _, _ in fg}, {120})        # стена x = const
        self.assertLess(min(z for *_, z in fg), 0)            # текст уходит в -z


if __name__ == "__main__":
    unittest.main()
