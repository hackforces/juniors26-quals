import base64
import hashlib
import io
import json
import sqlite3
import struct
import tempfile
import zipfile
from pathlib import Path


def stream_xor(data, key, nonce):
    output, counter = bytearray(), 0
    while len(output) < len(data):
        output.extend(hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(a ^ b for a, b in zip(data, output))


def packet(payload, seconds):
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    ip = bytes.fromhex("450000") + struct.pack("!H", 20 + 8 + len(payload)) + bytes.fromhex("0012400040110000c0000214")
    udp = struct.pack("!HHHH", 47321, 4433, 8 + len(payload), 0)
    frame = ethernet + ip + udp + payload
    return struct.pack("<IIII", seconds, 0, len(frame), len(frame)) + frame


def pcap(payloads):
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    return header + b"".join(packet(payload, seconds) for payload, seconds in payloads)


def build(flag, root):
    root.mkdir(parents=True, exist_ok=True)
    android_id = hashlib.sha256(b"abbey-device" + flag.encode()).hexdigest()[:16]
    seed = hashlib.sha256(b"abbey-seed" + flag.encode()).digest()
    key = hashlib.sha256(seed + android_id.encode()).digest()
    nonce = hashlib.sha256(b"abbey-nonce" + flag.encode()).digest()[:12]
    uuid = hashlib.sha256(b"abbey-attachment" + flag.encode()).hexdigest()[:16]
    decoy_uuid_one, decoy_uuid_two = "3c9f5a1e07b264d8", "a68e40d2193f7cb5"
    ciphertext = stream_xor(flag.encode(), key, nonce)
    with tempfile.TemporaryDirectory() as directory:
        database = Path(directory) / "messages.db"
        connection = sqlite3.connect(database)
        connection.execute("create table messages(ts text, conversation text, attachment_uuid text, note text)")
        connection.execute("insert into messages values(?,?,?,?)", ("2050-06-04T21:52:09Z", "abbey-12", decoy_uuid_one, "incoming attachment queued"))
        connection.execute("insert into messages values(?,?,?,?)", ("2050-06-04T22:03:44Z", "abbey-31", decoy_uuid_two, "chat backup scheduled"))
        connection.execute("insert into messages values(?,?,?,?)", ("2050-06-04T22:17:31Z", "abbey-47", uuid, "outgoing attachment queued"))
        connection.commit(); connection.close()
        with zipfile.ZipFile(root / "abbey.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            archive.write(database, "data/data/org.newbaker.courier/databases/messages.db")
            archive.writestr("bugreport/notifications.txt", "22:17:30 notification conversation=abbey-47 title=Attachment prepared\n")
            archive.writestr("data/data/org.newbaker.courier/shared_prefs/device.xml", f"<map><string name=\"upload_seed\">{base64.b64encode(seed).decode()}</string></map>\n")
            archive.writestr("data/system/users/0/settings_secure.xml", f"<settings><setting name=\"android_id\" value=\"{android_id}\" /></settings>\n")
            archive.writestr("app-log.txt", "upload key = SHA-256(upload_seed || android_id); stream = SHA-256(key || nonce || counter_be_32), XOR\n")
            payload = b"MOBILE/" + uuid.encode() + b"/" + nonce.hex().encode() + b"/" + ciphertext.hex().encode()
            decoy_one = b"MOBILE/" + decoy_uuid_one.encode() + b"/0f3a19c5d27e84b60921a4cd/e8d4106f2b3795c0a184e6d2fb09c35a"
            decoy_two = b"MOBILE/" + decoy_uuid_two.encode() + b"/4b902e7d1c5a83640f2d9be1/51c6e0a9d4827f3b05da9138e6c2047f"
            archive.writestr("network/night-upload.pcap", pcap([(decoy_one, 1760000386), (payload, 1760000400), (decoy_two, 1760000414)]))
