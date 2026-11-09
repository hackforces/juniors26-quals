import hashlib
import io
import json
import struct
import tarfile
from pathlib import Path


def stream_xor(data, key, nonce):
    output, counter = bytearray(), 0
    while len(output) < len(data):
        output.extend(hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(a ^ b for a, b in zip(data, output))


def pcap(records):
    result = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, payload in enumerate(records):
        eth = bytes.fromhex("102030405060aabbccddeeff0800")
        ip = bytes.fromhex("450000") + struct.pack("!H", 20 + 8 + len(payload)) + struct.pack("!H", index + 1) + bytes.fromhex("0000400011000000c6336409cb007109")
        udp = struct.pack("!HHHH", 43000, 4433, 8 + len(payload), 0)
        frame = eth + ip + udp + payload
        result.extend(struct.pack("<IIII", 1760000500 + index, 0, len(frame), len(frame)) + frame)
    return bytes(result)


def build(flag, root):
    root.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(b"amsterdam-session" + flag.encode()).digest()[:16]
    nonce = hashlib.sha256(b"amsterdam-nonce" + flag.encode()).digest()[:12]
    stream = stream_xor(flag.encode(), key, nonce)
    session = hashlib.sha256(b"amsterdam-stream" + flag.encode()).hexdigest()[:10]
    records = []
    for sequence, block in enumerate([stream[i:i + 9].ljust(9, b"\0") for i in range(0, len(stream), 9)]):
        shards = [block[offset:offset + 3] for offset in range(0, 9, 3)]
        parity = bytes(shards[0][i] ^ shards[1][i] ^ shards[2][i] for i in range(3))
        missing = sequence % 3
        for slot, shard in enumerate(shards):
            if slot != missing:
                records.append(f"IR/{session}/{sequence:03d}/{slot}/".encode() + shard.hex().encode())
        records.append(f"IR/{session}/{sequence:03d}/P/".encode() + parity.hex().encode())
    records.extend([b"dns-noise.example", b"telemetry/idle"])
    files = {
        "volatility/windows.pslist.txt": "PID PPID ImageFileName\n888 4 services.exe\n4172 888 ledger-sync.exe\n3396 888 telemetry-agent.exe\n5108 888 backup-sync.exe\n7284 888 indexer.exe\n",
        "volatility/windows.psscan.txt": "PID PPID ImageFileName\n4172 888 ledger-sync.exe ExitTime=none\n3396 888 telemetry-agent.exe ExitTime=none\n5108 888 backup-sync.exe ExitTime=none\n7284 888 indexer.exe ExitTime=none\n",
        "volatility/windows.netscan.txt": "PID LocalAddr ForeignAddr State\n4172 10.42.0.7:43000 203.0.113.9:4433 ESTABLISHED\n",
        "volatility/windows.malfind.txt": f"PID 4172 ledger-sync.exe anonymous RWX\nProcessGuid: {{4A7E-4172}}\nSESSION={session}\nSESSION_KEY: see the EventID 1 process whose ProcessGuid matches (above) — key is in its CommandLine\nSTREAM=SHA-256(key || nonce || counter_be_32), XOR\n",
        "logs/sysmon.jsonl": json.dumps({"EventID": 1, "UtcTime": "2050-06-03T03:14:18Z", "ProcessGuid": "{4A7E-4172}", "Image": "ledger-sync.exe", "CommandLine": f"ledger-sync.exe --sync --session-key {key.hex()}"}) + "\n" + json.dumps({"EventID": 3, "UtcTime": "2050-06-03T03:14:20Z", "ProcessGuid": "{4A7E-4172}", "DestinationIp": "203.0.113.9", "DestinationPort": 4433}) + "\n" + json.dumps({"EventID": 1, "UtcTime": "2050-06-03T03:14:22Z", "ProcessGuid": "{D3C0-0001}", "Image": "telemetry-agent.exe", "CommandLine": "telemetry-agent.exe --report periodic"}) + "\n" + json.dumps({"EventID": 1, "UtcTime": "2050-06-03T03:14:24Z", "ProcessGuid": "{D3C0-0002}", "Image": "backup-sync.exe", "CommandLine": "backup-sync.exe --target archive"}) + "\n" + json.dumps({"EventID": 1, "UtcTime": "2050-06-03T03:14:26Z", "ProcessGuid": "{D3C0-0003}", "Image": "indexer.exe", "CommandLine": "indexer.exe --rebuild catalog"}) + "\n",
        "README.txt": "Volatility 3 investigation exports, Sysmon timeline and packet capture from the same incident. One data shard is absent in every IR group; P is XOR parity.\n",
        "network/amsterdam.pcap": pcap(records),
        "network/nonce.txt": nonce.hex() + "\n",
    }
    with tarfile.open(root / "amsterdam.tar.gz", "w:gz") as archive:
        for name, value in files.items():
            data = value.encode() if isinstance(value, str) else value
            info = tarfile.TarInfo(name); info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
