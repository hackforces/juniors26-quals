#!/usr/bin/env python3
"""retro-heap: раздача retro-heap-files.zip (stdlib only).

HTTP (PORT_HTTP, по умолчанию 8008): GET / отдаёт retro-heap-files.zip
(бинарник chal + libc.so.6 + ld-linux + run.sh) как вложение.
"""

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HANDOUT_PATH = Path(os.environ.get("HANDOUT_PATH", "/www/retro-heap-files.zip"))
FILENAME = "retro-heap-files.zip"


class Handout(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?", 1)[0] not in ("/", "/" + FILENAME):
            self.send_error(404)
            return
        data = HANDOUT_PATH.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", f'attachment; filename="{FILENAME}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command == "GET":
            self.wfile.write(data)

    do_HEAD = do_GET

    def log_message(self, *a):
        pass


def main():
    port = int(os.environ.get("PORT_HTTP", "8008"))
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handout)
    print(f"[http] :{port}  (handout {FILENAME})", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
