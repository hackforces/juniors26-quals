#!/usr/bin/env python3
"""Birthday-коллизия на 24-битной печати SHA-256(case_id || card)."""
import base64
import hashlib
import json
import sys
import urllib.request

root = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13410").rstrip("/")
case_id = json.load(urllib.request.urlopen(root + "/"))["case_id"].encode()
seen = {}
for counter in range(1 << 20):
    card = f"tokyo-card-{counter}".encode()
    digest = hashlib.sha256(case_id + card).digest()[:3]
    if digest in seen:
        payload = json.dumps({
            "first": base64.b64encode(seen[digest]).decode(),
            "second": base64.b64encode(card).decode(),
        }).encode()
        request = urllib.request.Request(root + "/submit", data=payload, headers={"Content-Type": "application/json"})
        print(json.load(urllib.request.urlopen(request))["message"])
        break
    seen[digest] = card
else:
    sys.exit("no collision found")
