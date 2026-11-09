import hashlib
import json
import random
from pathlib import Path

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (55066263022277343669578718895168534326250603453777594175500187360389116729240,
     32670510020758816978083085130507043184471273380659243275938904335757337482424)


def add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def multiply(value, point=G):
    result = None
    while value:
        if value & 1:
            result = add(result, point)
        point = add(point, point)
        value >>= 1
    return result


def stream_xor(data, key, nonce):
    output, counter = bytearray(), 0
    while len(output) < len(data):
        output.extend(hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(a ^ b for a, b in zip(data, output))


def build(flag, root):
    root.mkdir(parents=True, exist_ok=True)
    rng = random.Random(int.from_bytes(hashlib.sha512(flag.encode()).digest(), "big"))
    private = rng.randrange(1, N)
    tail = rng.randrange(1, 1 << 32)
    captures = []
    for index in range(7):
        while True:
            high = rng.randrange(1, 1 << 224)
            nonce = (high << 32) | tail
            if nonce < N:
                break
        message = f"telemetry-frame-{index}".encode()
        digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
        r = multiply(nonce)[0] % N
        s = pow(nonce, -1, N) * (digest + r * private) % N
        captures.append({"message": message.decode(), "z": str(digest), "r": str(r), "s": str(s), "nonce_high": str(high)})
    nonce = hashlib.sha256(b"final-case-nonce" + flag.encode()).digest()[:12]
    key = hashlib.sha256(private.to_bytes(32, "big")).digest()
    report = {
        "curve": "secp256k1",
        "public_key": [str(value) for value in multiply(private)],
        "telemetry": "The low 32-bit counter register was stuck for every capture; nonce_high is k >> 32.",
        "captures": captures,
        "message_cipher": {
            "nonce": nonce.hex(),
            "stream": "SHA-256(SHA-256(private_key_be_32) || nonce || counter_be_32), XOR",
            "ciphertext": stream_xor(flag.encode(), key, nonce).hex(),
        },
    }
    (root / "telemetry.json").write_text(json.dumps(report, indent=2))
