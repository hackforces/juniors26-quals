import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from gen import build
flag=os.environ.get('CTF_FLAG','')
if not flag or '\n' in flag: raise RuntimeError('CTF_FLAG must be a non-empty single-line personal value')
root=Path('/tmp/public'); build(flag,root)
class H(SimpleHTTPRequestHandler):
 def __init__(self,*a,**k): super().__init__(*a,directory=root,**k)
 def do_GET(self):
  if self.path=='/health': self.send_response(200); self.end_headers(); self.wfile.write(b'ok'); return
  super().do_GET()
ThreadingHTTPServer(('0.0.0.0',8080),H).serve_forever()
