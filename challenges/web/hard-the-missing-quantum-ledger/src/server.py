from http.server import BaseHTTPRequestHandler, HTTPServer
import base64, hashlib, hmac, json, os
KEY = b"yard-archive-2050-retired-key"
def b64(v): return base64.urlsafe_b64encode(v).rstrip(b"=")
class App(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/": body, code = b"<h1>Scotland Yard ledger</h1><p>A visitor badge grants only lobby access.</p><script src='/assets/terminal.js'></script>", 200
        elif self.path == "/assets/terminal.js":
            body, code = b'''// Compatibility client for Yard terminals
window.badgeEndpoint = "/badge";
window.ledgerEndpoint = "/vault";
window.compatibilityManifest = "/assets/old-manifest.json";
// The badge endpoint returns the value stored in the badge cookie.
''', 200
        elif self.path == "/assets/old-manifest.json": body, code = json.dumps({"badge_format":"base64url(json).base64url(hmac-sha256)","legacy_signing_key":KEY.decode(),"example":{"role":"visitor"}}).encode(), 200
        elif self.path == "/badge":
            payload=b64(b'{"role":"visitor"}'); body, code = payload+b"."+b64(hmac.new(KEY,payload,hashlib.sha256).digest()), 200
        elif self.path == "/vault":
            token = self.headers.get("Cookie", "").removeprefix("badge=").encode()
            try:
                payload, sig = token.split(b".",1)
                good = b64(hmac.new(KEY,payload,hashlib.sha256).digest())
                role = json.loads(base64.urlsafe_b64decode(payload+b"="*(-len(payload)%4)))["role"]
                if hmac.compare_digest(sig,good) and role == "inspector": body, code = os.environ["CTF_FLAG"].encode(), 200
                else: body, code = b"vault is inspector-grade; badge rejected", 403
            except Exception: body, code = b"invalid badge", 400
        else: self.send_error(404); return
        self.send_response(code)
        content_type = ("text/html; charset=utf-8" if self.path == "/" else
                        "application/javascript" if self.path.endswith(".js") else
                        "application/json" if self.path.endswith(".json") else
                        "text/plain; charset=utf-8")
        self.send_header("Content-Type", content_type); self.end_headers(); self.wfile.write(body)
    def log_message(self,*_): pass
HTTPServer(("0.0.0.0",8080), App).serve_forever()
