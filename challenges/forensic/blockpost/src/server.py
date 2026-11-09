#!/usr/bin/env python3
"""
Blockpost: раздача хэндаута (stdlib only).

HTTP (PORT, по умолчанию 8089): GET / отдаёт blockpost.zip (challenge.pcap + latest.log)
как вложение. Сервис только раздаёт файл; флага в контейнере нет нигде, кроме
зашифрованных координат блоков внутри pcap (архив собран на этапе docker build).
"""

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HANDOUT_PATH = os.environ.get("HANDOUT_PATH", "./blockpost.zip")
PORT = int(os.environ.get("PORT", "8089"))
NAME = "blockpost.zip"


class Handout(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?", 1)[0] not in ("/", "/" + NAME):
            self.send_error(404)
            return
        data = Path(HANDOUT_PATH).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", f'attachment; filename="{NAME}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command == "GET":
            self.wfile.write(data)

    do_HEAD = do_GET

    def log_message(self, *a):
        pass


def main():
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handout)
    print(f"[http] :{PORT}  (handout {NAME})", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
