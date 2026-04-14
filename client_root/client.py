#!/usr/bin/env python3
"""
FSS Baseline Client - Deliberately Insecure
Sends plaintext JSON, accepts any server response without verification.
"""

import socket
import json

# MITM node acts as the relay; client connects to it
SERVER_HOST = "10.0.0.2"   # MITM-facing IP (adjust per setup_net)
SERVER_PORT = 9000

token = None
current_user = None


def send_json(sock, obj):
    line = json.dumps(obj) + "\n"
    sock.sendall(line.encode("utf-8"))


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


def connect():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    return sock


def do_login(sock):
    global token, current_user
    username = input("  Username: ").strip()
    password = input("  Password: ").strip()
    send_json(sock, {"action": "AUTH", "username": username, "password": password})
    resp = recv_json(sock)
    if resp and resp.get("status") == "ok":
        token = resp["token"]
        current_user = username
        print(f"  Logged in as '{username}'. Token: {token}")
    else:
        print(f"  Login failed: {resp.get('message', 'unknown error')}")


def do_create(sock):
    username = input("  New username: ").strip()
    password = input("  New password: ").strip()
    send_json(sock, {"action": "CREATE", "username": username, "password": password})
    resp = recv_json(sock)
    if resp and resp.get("status") == "ok":
        print(f"  Account created for '{username}'.")
    else:
        print(f"  Error: {resp.get('message', 'unknown error')}")


def do_list(sock):
    if not token:
        print("  Not logged in.")
        return
    send_json(sock, {"action": "LIST", "token": token})
    resp = recv_json(sock)
    if resp and resp.get("status") == "ok":
        files = resp.get("files", [])
        if not files:
            print("  No files.")
        for f in files:
            print(f"  {f['name']}  ts={f['modified_ts']}  sha256={f['digest']}")
    else:
        print(f"  Error: {resp.get('message', 'unknown error')}")


def do_upload(sock):
    if not token:
        print("  Not logged in.")
        return
    filename = input("  Filename: ").strip()
    print("  Enter file content (type END on a line by itself to finish):")
    lines = []
    while True:
        line = input()
        if line == "END":
            break
        lines.append(line)
    content = "\n".join(lines)
    send_json(sock, {"action": "UPLOAD", "token": token, "filename": filename, "content": content})
    resp = recv_json(sock)
    if resp and resp.get("status") == "ok":
        print(f"  Upload complete. ts={resp.get('ts')}  sha256={resp.get('sha256')}")
    else:
        print(f"  Error: {resp.get('message', 'unknown error')}")


def do_download(sock):
    if not token:
        print("  Not logged in.")
        return
    filename = input("  Filename: ").strip()
    send_json(sock, {"action": "DOWNLOAD", "token": token, "filename": filename})
    resp = recv_json(sock)
    if resp and resp.get("status") == "ok":
        print(f"  File: {resp.get('filename')}")
        print(f"  ts={resp.get('modified_ts')}  sha256={resp.get('sha256')}")
        print("  Content:")
        print(resp.get("content", ""))
    else:
        print(f"  Error: {resp.get('message', 'unknown error')}")


def do_logout(sock):
    global token, current_user
    if not token:
        print("  Not logged in.")
        return
    send_json(sock, {"action": "LOGOUT", "token": token})
    resp = recv_json(sock)
    if resp and resp.get("status") == "ok":
        print(f"  {resp.get('message')}")
        token = None
        current_user = None
    else:
        print(f"  Error: {resp.get('message', 'unknown error')}")


MENU = """
=== FSS Client ===
1. Login
2. Create account
3. List files
4. Upload file
5. Download file
6. Logout
7. Quit
"""

ACTIONS = {
    "1": do_login,
    "2": do_create,
    "3": do_list,
    "4": do_upload,
    "5": do_download,
    "6": do_logout,
}


def main():
    sock = connect()
    print(f"Connected to {SERVER_HOST}:{SERVER_PORT}")
    try:
        while True:
            print(MENU)
            choice = input("Choice: ").strip()
            if choice == "7":
                print("Bye.")
                break
            action = ACTIONS.get(choice)
            if action:
                action(sock)
            else:
                print("  Invalid choice.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
