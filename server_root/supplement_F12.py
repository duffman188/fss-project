#!/usr/bin/env python3
"""
supplement_F12.py - Plaintext Password Storage
Finding: F-12
Violated: R1, R12
Run in the server shell (or any shell with access to server_root/).
Demonstrates that users.json stores passwords in plaintext.
Any party with read access to the server filesystem can immediately
obtain all credentials without any cryptographic attack.
"""

import json
import os
import sys

USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")


def main():
    if not os.path.exists(USERS_FILE):
        print(f"[F-12] users.json not found at {USERS_FILE}")
        sys.exit(1)

    with open(USERS_FILE, "r") as f:
        users = json.load(f)

    print(f"[F-12] Plaintext credentials found in users.json:\n")
    print(f"  {'Username':<20} {'Password'}")
    print(f"  {'-'*20} {'-'*20}")
    for username, data in users.items():
        password = data.get("password", "<not found>")
        print(f"  {username:<20} {password}")

    print(f"\n[F-12] {len(users)} account(s) fully exposed without any decryption.")
    print(f"[F-12] Violation: R1 (file contents — here credentials — readable by unentitled party)")
    print(f"[F-12] Violation: R12 (no trust establishment; secrets not protected at rest)")


if __name__ == "__main__":
    main()
