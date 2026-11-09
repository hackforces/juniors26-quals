#!/usr/bin/env python3
"""
mini-vm challenge service (stdlib only).

Two listeners:

  * HTTP (PORT_HTTP, default 8000) - hands out the downloadable artifact
    (mini-vm-files.zip, or the raw binary) for reverse engineering.

  * TCP  (PORT_NC, default 1337) - the interactive challenge. Per connection
    it picks a random 16-byte x0, computes the target y = P(x0) by running the
    oracle binary, and asks the player to send back x with P(x) == y within a
    time limit. P is a bijection, so the unique answer is x = x0 = P^-1(y).
    After ROUNDS successful rounds it prints the flag (env FLAG).

The flag exists ONLY here (env). The binary contains no secret; the server
uses it purely as the authoritative forward oracle for both challenge
generation and verification, so server and handout can never disagree.
"""

import os
import socket
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CHAL_PATH = os.environ.get("CHAL_PATH", "./minivm")
_ctf_flag = os.environ.get("CTF_FLAG")
if not _ctf_flag:
    raise SystemExit("server: CTF_FLAG env must be set")
FLAG = _ctf_flag
TIME_LIMIT = float(os.environ.get("TIME_LIMIT", "20"))
ROUNDS = int(os.environ.get("ROUNDS", "1"))
PORT_NC = int(os.environ.get("PORT_NC", "1337"))
PORT_HTTP = int(os.environ.get("PORT_HTTP", "8000"))
HANDOUT = os.environ.get("HANDOUT_PATH", "")   # optional mini-vm-files.zip
BLOCK = 16

BANNER = (
    b"== mini-vm oracle ==\n"
    b"The attached binary computes P(x) for a 16-byte block x (32 hex chars).\n"
    b"Prove you can invert it: for each challenge y, send x such that P(x)=y.\n"
    + f"You have {TIME_LIMIT:g}s and must clear {ROUNDS} round(s).\n".encode()
)


def oracle(block: bytes) -> bytes:
    """Run the binary forward: returns P(block) (16 bytes)."""
    r = subprocess.run([CHAL_PATH], input=block.hex().encode() + b"\n",
                       capture_output=True, timeout=5)
    out = r.stdout.decode(errors="replace").strip()
    return bytes.fromhex(out)


def recv_line(conn: socket.socket, limit: int = 128) -> bytes:
    buf = bytearray()
    while len(buf) < limit:
        ch = conn.recv(1)
        if not ch:
            break
        if ch in (b"\n", b"\r"):
            if buf:
                break
            continue
        buf += ch
    return bytes(buf)


def handle_nc(conn: socket.socket, addr) -> None:
    conn.settimeout(TIME_LIMIT)
    try:
        conn.sendall(BANNER)
        for rnd in range(ROUNDS):
            x0 = os.urandom(BLOCK)
            y = oracle(x0)
            conn.sendall(f"\n[round {rnd + 1}/{ROUNDS}] y = ".encode()
                         + y.hex().encode() + b"\nx = ")
            line = recv_line(conn)
            try:
                x = bytes.fromhex(line.decode().strip())
            except Exception:
                conn.sendall(b"bad input\n")
                return
            if len(x) != BLOCK or oracle(x) != y:
                conn.sendall(b"nope\n")
                return
        conn.sendall(b"\ncorrect. flag: " + FLAG.encode() + b"\n")
    except (socket.timeout, BrokenPipeError, ConnectionResetError):
        try:
            conn.sendall(b"\ntimeout\n")
        except OSError:
            pass
    except Exception as e:
        try:
            conn.sendall(f"error: {e}\n".encode())
        except OSError:
            pass
    finally:
        conn.close()


def nc_server() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT_NC))
    s.listen(64)
    print(f"[nc]   listening on :{PORT_NC} (time limit {TIME_LIMIT:g}s, "
          f"{ROUNDS} round(s))", flush=True)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_nc, args=(conn, addr), daemon=True).start()


class Handout(BaseHTTPRequestHandler):
    def _send(self, data: bytes, name: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", f'attachment; filename="{name}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if HANDOUT and Path(HANDOUT).exists():
            self._send(Path(HANDOUT).read_bytes(), "mini-vm-files.zip")
        else:
            self._send(Path(CHAL_PATH).read_bytes(), "minivm")

    do_HEAD = do_GET

    def log_message(self, *a):
        pass


def main() -> None:
    threading.Thread(target=nc_server, daemon=True).start()
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT_HTTP), Handout)
    print(f"[http] listening on :{PORT_HTTP} (handout download)", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
