#!/usr/bin/env python3

import os
import re
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from spn import Params, BLOCK

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
BIN = r"/solve/minivm"


_TLS = os.environ.get("TLS")
USE_TLS = (_TLS not in ("0", "", "no", "false", "False")) if _TLS is not None else (PORT == 443)
_SSL_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


def connect(host: str, port: int, timeout: float):
    sock = socket.create_connection((host, port), timeout=timeout)
    if USE_TLS:
        sock = _SSL_CTX.wrap_socket(sock, server_hostname=host)
    return sock


P = Params()


# --------------------------------------------------------------------------- #
# intended solve: algebraic inverse of P
# --------------------------------------------------------------------------- #
def invert(y: bytes) -> bytes:
    return P.inverse(y)


def invert_z3(y: bytes, params: Params, timeout_s: int = 30):
    try:
        import z3
    except ImportError:
        return None
    from spn import SR_SRC
    sbox = z3.Array("sbox", z3.BitVecSort(8), z3.BitVecSort(8))
    m2 = z3.Array("m2", z3.BitVecSort(8), z3.BitVecSort(8))
    m3 = z3.Array("m3", z3.BitVecSort(8), z3.BitVecSort(8))
    s = z3.Solver()
    s.set("timeout", timeout_s * 1000)
    for i in range(256):
        s.add(sbox[i] ==
         params.sbox[i])
        s.add(m2[i] == params.mul[2][i])
        s.add(m3[i] == params.mul[3][i])
    st = [z3.BitVec(f"x{i}", 8) for i in range(16)]
    x_in = list(st)
    for r in range(params.rounds):
        st = [st[i] ^ params.rcon[r][i] for i in range(16)]
        st = [sbox[st[i]] for i in range(16)]
        st = [st[SR_SRC[i]] for i in range(16)]
        out = [None] * 16
        for c in range(4):
            a, b, cc, d = st[4 * c], st[4 * c + 1], st[4 * c + 2], st[4 * c + 3]
            out[4 * c + 0] = m2[a] ^ m3[b] ^ cc ^ d
            out[4 * c + 1] = a ^ m2[b] ^ m3[cc] ^ d
            out[4 * c + 2] = a ^ b ^ m2[cc] ^ m3[d]
            out[4 * c + 3] = m3[a] ^ b ^ cc ^ m2[d]
        st = out
    st = [st[i] ^ params.rcon[params.rounds][i] for i in range(16)]
    for i in range(16):
        s.add(st[i] == y[i])
    if s.check() != z3.sat:
        return None
    m = s.model()
    return bytes(m[x_in[i]].as_long() for i in range(16))


# --------------------------------------------------------------------------- #
# service client
# --------------------------------------------------------------------------- #
def recv_until(conn, needle: bytes, limit: int = 65536) -> bytes:
    buf = bytearray()
    while needle not in buf and len(buf) < limit:
        ch = conn.recv(4096)
        if not ch:
            break
        buf += ch
    return bytes(buf)


def solve_service(host: str, port: int, inverter=invert) -> str:
    with connect(host, port, 30) as conn:
        # the banner + first "y = .. / x = " prompt arrive together
        blob = recv_until(conn, b"x = ")
        m = re.search(rb"clear (\d+) round", blob)
        rounds = int(m.group(1)) if m else 1
        for _ in range(rounds):
            if b"x = " not in blob:
                blob = recv_until(conn, b"x = ")
            ym = re.search(rb"y = ([0-9a-f]{32})", blob)
            if not ym:
                raise SystemExit(f"[!] no challenge in: {blob!r}")
            x = inverter(bytes.fromhex(ym.group(1).decode()))
            conn.sendall(x.hex().encode() + b"\n")
            blob = b""
        tail = recv_until(conn, b"}", limit=4096)
        fm = re.search(r"(?i)(innoctf|ctf|flag)\{[^}]*\}", tail.decode(errors="replace"))
        if not fm:
            raise SystemExit(f"[!] no flag in response: {tail!r}")
        return fm.group(0)


# --------------------------------------------------------------------------- #
# honesty checks
# --------------------------------------------------------------------------- #
def honesty_checks() -> None:
    print("[*] honesty checks")

    # local binary forward == spn.py forward (if the binary is present)
    if Path(BIN).exists():
        ok = True
        for _ in range(200):
            xb = os.urandom(16)
            r = subprocess.run([BIN], input=xb.hex().encode() + b"\n",
                               capture_output=True, timeout=5)
            if bytes.fromhex(r.stdout.decode().strip()) != P.forward(xb):
                ok = False
                break
        print(f"    - binary forward == spn.py          : {'OK' if ok else 'FAIL'}")
        assert ok

    # wrong answer is rejected
    try:
        with connect(HOST, PORT, 10) as conn:
            recv_until(conn, b"x = ")
            conn.sendall(os.urandom(16).hex().encode() + b"\n")
            resp = recv_until(conn, b"\n", limit=256).decode(errors="replace")
        rej = "nope" in resp or "{" not in resp
        print(f"    - wrong answer rejected             : {'OK' if rej else 'FAIL'}")
        assert rej
    except OSError as e:
        print(f"    - wrong answer rejected             : SKIP ({e})")

    # slow (post-deadline) answer times out
    try:
        with connect(HOST, PORT, 30) as conn:
            blob = recv_until(conn, b"x = ")
            y = re.search(rb"y = ([0-9a-f]{32})", blob).group(1).decode()
            limit = float(re.search(rb"have ([\d.]+)s", blob).group(1))
            time.sleep(limit + 2)
            conn.sendall(invert(bytes.fromhex(y)).hex().encode() + b"\n")
            resp = recv_until(conn, b"\n", limit=256).decode(errors="replace")
        timed = "{" not in resp
        print(f"    - late answer times out             : {'OK' if timed else 'FAIL'}")
        assert timed
    except OSError as e:
        print(f"    - late answer times out             : SKIP ({e})")


def main() -> None:
    # quick self-check of the inverter against the local oracle, if present
    if Path(BIN).exists():
        x = os.urandom(16)
        r = subprocess.run([BIN], input=x.hex().encode() + b"\n",
                           capture_output=True, timeout=5)
        y = bytes.fromhex(r.stdout.decode().strip())
        assert invert(y) == x, "algebraic inverse mismatch"
        print("[+] algebraic inverse verified against the binary")

    try:
        import z3  # noqa: F401
        demo = Params(rounds=1)
        xd = os.urandom(16)
        zd = invert_z3(demo.forward(xd), demo, timeout_s=30)
        ok = zd is not None and demo.forward(zd) == demo.forward(xd)
        print(f"[+] z3 single-round model sanity check: "
              f"{'solved' if ok else 'timeout (full SPN is SMT-hard by design)'}")
    except ImportError:
        print("[~] z3 not installed; skipping SMT sanity check (optional)")

    t0 = time.time()
    flag = solve_service(HOST, PORT)
    print(f"[+] solved in {time.time() - t0:.2f}s")
    print(f"[+] FLAG: {flag}")

    honesty_checks()


if __name__ == "__main__":
    main()
