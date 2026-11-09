import base64
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


FLAG = os.environ.get("CTF_FLAG", "")
if not FLAG:
    raise RuntimeError("CTF_FLAG must be set and non-empty")
CASE_ID = hashlib.sha256(FLAG.encode()).hexdigest()[:12]


def seal(message):
    return hashlib.sha256(CASE_ID.encode() + message).digest()[:3]


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body):
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path == "/health":
            self.reply(200, {"ok": True})
        elif self.path == "/":
            self.reply(200, {
                "case_id": CASE_ID,
                "seal": "first 24 bits of SHA-256(case_id || card_bytes)",
                "submit": "POST JSON {first: base64, second: base64} to /submit",
            })
        else:
            self.reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/submit":
            self.reply(404, {"error": "not found"})
            return
        try:
            length = int(self.headers["Content-Length"])
            data = json.loads(self.rfile.read(length))
            first = base64.b64decode(data["first"], validate=True)
            second = base64.b64decode(data["second"], validate=True)
        except Exception:
            self.reply(400, {"error": "invalid cards"})
            return
        if first != second and seal(first) == seal(second):
            self.reply(200, {"message": FLAG})
        else:
            self.reply(403, {"error": "the seals differ"})

    def log_message(self, *_):
        pass


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
