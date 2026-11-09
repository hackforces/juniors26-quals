import socket
import ssl


context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="/opt/treaty/ca.crt")
context.load_cert_chain("/tmp/treaty-client.pem")
with socket.create_connection(("127.0.0.1", 9443), timeout=5) as raw:
    with context.wrap_socket(raw, server_hostname="treaty-archive") as client:
        print(client.recv(512).decode(), end="")
        command = input("archive> ")
        client.sendall((command + "\n").encode())
        print(client.recv(512).decode(), end="")
