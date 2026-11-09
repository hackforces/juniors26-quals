import hashlib
import json
import zipfile
from pathlib import Path


def stream_xor(data, key, nonce):
    output, counter = bytearray(), 0
    while len(output) < len(data):
        output.extend(hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(a ^ b for a, b in zip(data, output))


def build(flag, root):
    root.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(b"student-agent" + flag.encode()).digest()[:16]
    nonce = hashlib.sha256(b"student-nonce" + flag.encode()).digest()[:12]
    envelope = {"nonce": nonce.hex(), "stream": "SHA-256(key || nonce || counter_be_32), XOR", "ciphertext": stream_xor(flag.encode(), key, nonce).hex()}
    with zipfile.ZipFile(root / "students.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("volatility/windows.pstree.txt", "PID  PPID ImageFileName\n412  4    explorer.exe\n4172 412  case-agent.exe\n4188 412  chrome.exe\n")
        archive.writestr("volatility/windows.envars.txt", f"PID 692 svchost.exe\nCASE_ROLE=system-host\nPID 1204 explorer.exe\nCASE_ROLE=shell\nPID 4172 case-agent.exe\nCASE_SEAL_KEY={key.hex()}\nCASE_ROLE=night-lab\nPID 3356 RuntimeBroker.exe\nCASE_ROLE=broker\n")
        archive.writestr("sealed-note.json", json.dumps(envelope, indent=2))
        archive.writestr("README.txt", "Primary Volatility 3 exports from the volatile capture are included. The note was sealed by the failed laboratory agent.\n")
