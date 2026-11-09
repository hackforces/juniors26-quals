import hashlib
import os
import socketserver


class Desk(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"Red League information desk\nPresent the case number from /etc/red/card.\nnumber: ")
        number = self.rfile.readline(128).strip().decode(errors="ignore")
        expected = hashlib.sha256(os.environ["CTF_FLAG"].encode()).hexdigest()[:16]
        if number == expected:
            self.wfile.write((os.environ["CTF_FLAG"] + "\n").encode())
        else:
            self.wfile.write(b"The clerk cannot find that case.\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


Server(("127.0.0.1", 4587), Desk).serve_forever()
