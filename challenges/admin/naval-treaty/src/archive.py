import os
import socket
import ssl


context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain("/opt/treaty/server.crt", "/opt/treaty/server.key")
context.load_verify_locations("/opt/treaty/ca.crt")
context.verify_mode = ssl.CERT_REQUIRED

with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 9443))
    listener.listen(16)
    while True:
        raw, _ = listener.accept()
        try:
            with context.wrap_socket(raw, server_side=True) as client:
                client.sendall(b"Treaty archive ready. Commands: LIST; FETCH <epoch>\n")
                command = client.recv(256).decode(errors="ignore").strip()
                if command == "LIST":
                    client.sendall(b"sealed epochs: 2050.06.17-04, 2050.06.17-03\n")
                elif command == "FETCH 2050.06.17-04":
                    client.sendall((os.environ["CTF_FLAG"] + "\n").encode())
                else:
                    client.sendall(b"archive has no such bulletin\n")
        except ssl.SSLError:
            raw.close()
