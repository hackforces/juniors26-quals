from http.server import BaseHTTPRequestHandler, HTTPServer
import base64, os
FLAG = os.environ["CTF_FLAG"]
class App(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b"<h1>Irene's private archive</h1><p>The page looks ordinary. Watson says the client remembers more than it shows.</p><script src='/assets/client.js'></script>"
        elif self.path == "/assets/client.js":
            body = ("window.caseMemo = '" + base64.b64encode(FLAG.encode()).decode() + "';\n" +
                    "document.body.insertAdjacentHTML('beforeend','<p>Archive client loaded.</p>');").encode()
        else:
            self.send_error(404); return
        self.send_response(200); self.send_header("Content-Type", "text/javascript" if self.path.endswith(".js") else "text/html"); self.end_headers(); self.wfile.write(body)
    def log_message(self, *_): pass
HTTPServer(("0.0.0.0",8080), App).serve_forever()
