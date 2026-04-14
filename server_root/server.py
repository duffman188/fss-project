#!/usr/bin/env python3
"""
FSS Baseline Server - Deliberately Insecure
No encryption, no integrity checks, no replay protection.
"""

import socket
import json
import os
import hashlib
import time
import threading
import uuid

HOST = "0.0.0.0"
PORT = 9000
STORAGE_DIR = os.path.join(os.path.dirname(__file__), "server_storage")
USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")

# In-memory session store: token -> username
sessions = {}
sessions_lock = threading.Lock()


def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def user_dir(username):
    path = os.path.join(STORAGE_DIR, username)
    os.makedirs(path, exist_ok=True)
    return path


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def send_json(conn, obj):
    line = json.dumps(obj) + "\n"
    conn.sendall(line.encode("utf-8"))


def recv_json(conn):
    buf = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buf += chunk
        if b"\n" in buf:
            line, _ = buf.split(b"\n", 1)
            return json.loads(line.decode("utf-8"))


def handle_create(req, users):
    username = req.get("username", "").strip()
    password = req.get("password", "")
    if not username or not password:
        return {"status": "error", "message": "username and password required"}
    if username in users:
        return {"status": "error", "message": "username already exists"}
    # INSECURE: password stored in plaintext
    users[username] = {"password": password}
    save_users(users)
    user_dir(username)
    print(f"[CREATE] Account created for '{username}'")
    return {"status": "ok", "token": "account created"}


def handle_auth(req, users):
    username = req.get("username", "")
    password = req.get("password", "")
    stored = users.get(username)
    if stored is None or stored.get("password") != password:
        return {"status": "error", "message": "invalid credentials"}
    # INSECURE: token is a simple uuid, no signing, no expiry
    token = str(uuid.uuid4())
    with sessions_lock:
        sessions[token] = username
    print(f"[AUTH] '{username}' logged in, token={token}")
    return {"status": "ok", "token": token}


def handle_list(req, users):
    token = req.get("token", "")
    with sessions_lock:
        username = sessions.get(token)
    if username is None:
        return {"status": "error", "message": "invalid or expired token"}
    d = user_dir(username)
    files = []
    for fname in os.listdir(d):
        fpath = os.path.join(d, fname)
        if os.path.isfile(fpath):
            with open(fpath, "rb") as f:
                data = f.read()
            files.append({
                "name": fname,
                "modified_ts": os.path.getmtime(fpath),
                "digest": sha256_of(data)
            })
    print(f"[LIST] '{username}' listed {len(files)} file(s)")
    return {"status": "ok", "files": files}


def handle_upload(req, users):
    token = req.get("token", "")
    with sessions_lock:
        username = sessions.get(token)
    if username is None:
        return {"status": "error", "message": "invalid or expired token"}
    filename = req.get("filename", "").strip()
    content = req.get("content", "")
    if not filename:
        return {"status": "error", "message": "filename required"}
    # INSECURE: no path traversal check
    fpath = os.path.join(user_dir(username), filename)
    data = content.encode("utf-8")
    with open(fpath, "wb") as f:
        f.write(data)
    ts = os.path.getmtime(fpath)
    digest = sha256_of(data)
    print(f"[UPLOAD] '{username}' uploaded '{filename}'")
    return {
        "status": "ok",
        "message": f"upload complete for {username}",
        "ts": ts,
        "sha256": digest
    }


def handle_download(req, users):
    token = req.get("token", "")
    with sessions_lock:
        username = sessions.get(token)
    if username is None:
        return {"status": "error", "message": "invalid or expired token"}
    filename = req.get("filename", "").strip()
    if not filename:
        return {"status": "error", "message": "filename required"}
    # INSECURE: no path traversal check
    fpath = os.path.join(user_dir(username), filename)
    if not os.path.exists(fpath):
        return {"status": "error", "message": "file not found"}
    with open(fpath, "rb") as f:
        data = f.read()
    ts = os.path.getmtime(fpath)
    digest = sha256_of(data)
    print(f"[DOWNLOAD] '{username}' downloaded '{filename}'")
    return {
        "status": "ok",
        "filename": filename,
        "content": data.decode("utf-8"),
        "modified_ts": ts,
        "sha256": digest
    }


def handle_logout(req, users):
    token = req.get("token", "")
    with sessions_lock:
        username = sessions.pop(token, None)
    if username is None:
        return {"status": "error", "message": "invalid token"}
    print(f"[LOGOUT] '{username}' logged out")
    return {"status": "ok", "message": f"{username} logged out"}


HANDLERS = {
    "CREATE":   handle_create,
    "AUTH":     handle_auth,
    "LIST":     handle_list,
    "UPLOAD":   handle_upload,
    "DOWNLOAD": handle_download,
    "LOGOUT":   handle_logout,
}


def handle_client(conn, addr):
    print(f"[CONNECT] {addr}")
    users = load_users()
    try:
        while True:
            req = recv_json(conn)
            if req is None:
                break
            action = req.get("action", "").upper()
            handler = HANDLERS.get(action)
            if handler is None:
                resp = {"status": "error", "message": f"unknown action '{action}'"}
            else:
                try:
                    resp = handler(req, users)
                    # Reload users after writes
                    users = load_users()
                except Exception as e:
                    resp = {"status": "error", "message": str(e)}
            send_json(conn, resp)
    except Exception as e:
        print(f"[ERROR] {addr}: {e}")
    finally:
        conn.close()
        print(f"[DISCONNECT] {addr}")


def main():
    os.makedirs(STORAGE_DIR, exist_ok=True)
    if not os.path.exists(USERS_FILE):
        save_users({
            "alice": {"password": "password123"},
            "bob":   {"password": "letmein"}
        })
        print(f"[INIT] Created default users.json")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)
    print(f"[SERVER] Listening on {HOST}:{PORT}")
    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
