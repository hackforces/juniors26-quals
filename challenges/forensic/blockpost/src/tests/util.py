"""Общие хелперы тестов."""

import functools
import os
import subprocess
import sys
import tempfile

from mc_blockpost.generator import build

TASK_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
AUTHOR_SOLVER = os.path.join(TASK_DIR, "solve.py")


@functools.lru_cache(maxsize=None)
def cached_build(flag=None, axis="x", lossy=False):
    """Сборка дорогая (AES/CFB8 на чистом Python без `cryptography`) — кэшируем."""
    kw = {"axis": axis, "lossy": lossy}
    return build(flag, **kw) if flag else build(**kw)


def run_author_solver(res, expect):
    """Прогоняет самостоятельный solve.py (корень пакета) на файлах хэндаута."""
    with tempfile.TemporaryDirectory() as d:
        pcap, log = os.path.join(d, "challenge.pcap"), os.path.join(d, "latest.log")
        with open(pcap, "wb") as f:
            f.write(res["pcap"])
        with open(log, "w", encoding="utf-8") as f:
            f.write(res["log"])
        return subprocess.run([sys.executable, "-I", AUTHOR_SOLVER, pcap, log,
                               "--expect", expect], capture_output=True, text=True)
