import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from gen import build

flag = os.environ.get("CTF_FLAG", "")
if not flag:
    raise RuntimeError("CTF_FLAG must be set and non-empty")
root = Path("/srv/public/download")
build(flag, root)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/srv/public", **kwargs)

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        super().do_GET()


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
