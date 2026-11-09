from pathlib import Path
import hashlib
import zipfile


def rol(x, n):
    return ((x << n) | (x >> (8 - n))) & 255


def build(flag, root):
    root.mkdir(parents=True, exist_ok=True)
    seed = hashlib.sha256(flag.encode()).digest()[:8]
    plain = flag.encode()
    previous = 0
    transformed = []
    for i, byte in enumerate(plain):
        state = (previous * 13 + i * 29 + 7) & 255
        transformed.append(rol(byte ^ seed[i % 8] ^ state, (i % 5) + 1))
        previous = byte

    order = sorted(
        range(len(plain)),
        key=lambda i: hashlib.sha256(seed + i.to_bytes(2, "big")).digest(),
    )
    target = bytes(transformed[i] for i in order)
    device = '''# Fragment recovered from the archivist firmware
import hashlib
SEED = %r
TARGET = %r
def rol(x,n): return ((x<<n)|(x>>(8-n)))&255
def check(text):
 raw=text.encode(); previous=0; stage=[]
 for i,b in enumerate(raw):
  stage.append(rol(b ^ SEED[i%%8] ^ ((previous*13+i*29+7)&255), (i%%5)+1)); previous=b
 order=sorted(range(len(raw)),key=lambda i:hashlib.sha256(SEED+i.to_bytes(2,"big")).digest())
 return bytes(stage[i] for i in order) == TARGET
print("ritual accepted" if check(input("entry: ")) else "not the ritual")
''' % (seed, target)
    with zipfile.ZipFile(root / "musgrave-ritual.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("ritual_device.py", device)
        archive.writestr(
            "field_note.txt",
            "The device accepts exactly one entry and has no network access.\n",
        )
