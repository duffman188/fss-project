#!/usr/bin/env python3
"""
FSS Baseline MITM - Transparent Proxy
Sits between client and server. Baseline version simply forwards all traffic.
Attack variants (mitm_F01.py, mitm_F02.py, ...) are modified copies of this file.
"""

import socket
import threading
import json

# Addresses as configured by setup_net
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9000          # Port the client connects to (on MITM node)
SERVER_HOST  = "10.0.0.3"  # Real server IP (adjust per setup_net)
SERVER_PORT  = 9000


def forward(src, dst, label):
    """Forward bytes from src to dst, printing each JSON message."""
    buf = b""
    try:
        while True:
            chunk = src.recv(4096)
            if not chunk:
                break
            buf += chunk
            # Print each complete JSON line as it passes through
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    obj = json.loads(line.decode("utf-8"))
                    print(f"[{label}] {json.dumps(obj)}")
                except Exception:
                    print(f"[{label}] (raw) {line}")
                dst.sendall(line + b"\n")
    except Exception as e:
        print(f"[{label}] connection error: {e}")
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_connection(client_sock, client_addr):
    print(f"[MITM] Client connected from {client_addr}")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.connect((SERVER_HOST, SERVER_PORT))
    except Exception as e:
        print(f"[MITM] Cannot connect to server: {e}")
        client_sock.close()
        return

    # Two threads: one for each direction
    t1 = threading.Thread(
        target=forward,
        args=(client_sock, server_sock, "C->S"),
        daemon=True
    )
    t2 = threading.Thread(
        target=forward,
        args=(server_sock, client_sock, "S->C"),
        daemon=True
    )
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client_sock.close()
    server_sock.close()
    print(f"[MITM] Connection from {client_addr} closed")


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(5)
    print(f"[MITM] Listening on {LISTEN_HOST}:{LISTEN_PORT} -> forwarding to {SERVER_HOST}:{SERVER_PORT}")
    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=handle_connection, args=(conn, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
