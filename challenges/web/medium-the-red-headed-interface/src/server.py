from http.server import BaseHTTPRequestHandler, HTTPServer
import base64, os
class App(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = "<h1>Red-Headed League — customer desk</h1><p>Only the public desk is open.</p><p>Try the old, forgotten robots' instructions left from the previous version of the site before asking the operator.</p>".encode()
        elif self.path in ("/robots.txt", "/old/robots.txt"):
            body = (b"# Legacy crawl rules, forgotten after the site rewrite.\n"
                    b"# Nobody has updated these in years.\n"
                    b"User-agent: *\nDisallow: /console\n")
        elif self.path == "/console":
            body = b"<h1>Operator console</h1><p>The retired preview client requested the closed card from /api/card.</p><p>Preview requests are routed by the X-Case-Role header. The archivist profile may view the closed card.</p><p>The old client unpacked successful replies from Base64 before showing them.</p>"
        elif self.path == "/api/card":
            if self.headers.get("X-Case-Role") == "archivist":
                body = base64.b64encode(os.environ["CTF_FLAG"].encode())
            else:
                self.send_response(403); self.end_headers(); self.wfile.write(b"public desk only"); return
        else:
            self.send_error(404); return
        content_type = "text/plain; charset=utf-8" if self.path.endswith("robots.txt") or self.path.startswith("/api/") else "text/html; charset=utf-8"
        self.send_response(200); self.send_header("Content-Type", content_type); self.end_headers(); self.wfile.write(body)
    def log_message(self, *_): pass
HTTPServer(("0.0.0.0",8080), App).serve_forever()
