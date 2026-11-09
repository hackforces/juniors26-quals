import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from generate import build

root = Path('/srv/public')
flag = os.environ.get('CTF_FLAG')
if not flag:
    raise RuntimeError('CTF_FLAG must be supplied by the personal challenge runtime')
build(flag, root)

class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200); self.end_headers(); self.wfile.write(b'ok'); return
        if self.path in ('/', '/download/case.zip', '/download/empty-house.zip'):
            self.path = '/empty-house.zip'
        return super().do_GET()

os.chdir(root)
ThreadingHTTPServer(('0.0.0.0', int(os.environ.get('PORT', '8080'))), Handler).serve_forever()
