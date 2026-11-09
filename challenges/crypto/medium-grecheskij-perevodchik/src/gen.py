import hashlib
import json
import random
from pathlib import Path


def is_prime(value):
    if value < 2:
        return False
    for prime in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if value % prime == 0:
            return value == prime
    d, power = value - 1, 0
    while not d & 1:
        d //= 2
        power += 1
    for base in (2, 3, 5, 7, 11, 13, 17):
        if base >= value:
            continue
        result = pow(base, d, value)
        if result in (1, value - 1):
            continue
        for _ in range(power - 1):
            result = result * result % value
            if result == value - 1:
                break
        else:
            return False
    return True


def prime(rng):
    while True:
        value = rng.getrandbits(160) | 1 | (1 << 159)
        if is_prime(value):
            return value


def xor_stream(data, key, nonce):
    output = bytearray()
    counter = 0
    while len(output) < len(data):
        output.extend(hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(a ^ b for a, b in zip(data, output))


def build(flag, root):
    root.mkdir(parents=True, exist_ok=True)
    seed = int.from_bytes(hashlib.sha512(flag.encode()).digest(), "big")
    rng = random.Random(seed)
    shared = prime(rng)
    target_other = prime(rng)
    target_n = shared * target_other
    certificates = [{"id": "athens-archive", "n": str(target_n)}]
    certificates.append({"id": "corinth-relay", "n": str(shared * prime(rng))})
    for index in range(14):
        certificates.append({"id": f"office-{index:02d}", "n": str(prime(rng) * prime(rng))})
    rng.shuffle(certificates)
    session_key = hashlib.sha256(b"greek-session" + flag.encode()).digest()[:16]
    nonce = hashlib.sha256(b"greek-nonce" + flag.encode()).digest()[:12]
    wrapped = pow(int.from_bytes(session_key, "big"), 65537, target_n)
    registry = {
        "target": "athens-archive",
        "public_exponent": 65537,
        "certificates": certificates,
        "wrapped_session_key": str(wrapped),
        "stream": "SHA-256(session_key || nonce || counter_be_32), XOR",
        "nonce": nonce.hex(),
        "ciphertext": xor_stream(flag.encode(), session_key, nonce).hex(),
    }
    (root / "registry.json").write_text(json.dumps(registry, indent=2))
