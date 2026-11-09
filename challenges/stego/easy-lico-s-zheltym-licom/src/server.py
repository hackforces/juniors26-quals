import os
from http.server import SimpleHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from gen import build
flag=os.environ.get('CTF_FLAG','')
if not flag or '\n' in flag: raise RuntimeError('FLAG must be a non-empty single-line personal value')
r=Path('/tmp/public');build(flag,r)
class H(SimpleHTTPRequestHandler):
 def __init__(s,*a,**k):super().__init__(*a,directory=r,**k)
 def do_GET(s):
  if s.path=='/health':s.send_response(200);s.end_headers();return
  super().do_GET()
ThreadingHTTPServer(('0.0.0.0',8080),H).serve_forever()
