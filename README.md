# FSS Project — Stage 1: Baseline Analysis and Attack Demonstration

**Course:** COMP-3/4722  
**Stage:** 1 of 4  
**Due:** April 17, 2026

---

## Overview

This repository contains the baseline implementation of a deliberately insecure File Storage Service (FSS), along with 12 attack scripts demonstrating requirement violations under an active network adversary model.

The system consists of three components running in isolated Linux network namespaces:
- **Client** — connects to the server through the MITM node
- **MITM** — sits transparently between client and server
- **Server** — stores files and manages user accounts

---

## Repository Structure

```
fss-project/
├── client_root/
│   └── client.py              # FSS client
├── server_root/
│   ├── server.py              # FSS server
│   ├── users.json             # User accounts (alice, bob, carol)
│   └── supplement_F12.py     # F-12 attack script (run on server)
├── mitm_root/
│   ├── mitm.py                # Baseline transparent proxy
│   ├── mitm_F01.py            # F-01: Credential eavesdropping
│   ├── mitm_F02.py            # F-02: Upload content tampering
│   ├── mitm_F03.py            # F-03: Session token theft
│   ├── mitm_F04.py            # F-04: Upload replay attack
│   ├── mitm_F05.py            # F-05: Fake download injection
│   ├── mitm_F06.py            # F-06: Path traversal via filename
│   ├── mitm_F07.py            # F-07: Token fixation
│   ├── mitm_F08.py            # F-08: Response suppression
│   ├── mitm_F10.py            # F-10: Malformed input injection
│   ├── mitm_F11.py            # F-11: Cross-user token swap
│   └── supplement_F09.py     # F-09: Brute force (run on MITM)
├── findings_memo.txt          # Stage 1 findings memo (all 12 findings)
├── setup_net                  # Creates Linux network namespaces
└── enter                      # Opens shell in a namespace
```

---

## Setup

> **Requirements:** Linux (tested on Ubuntu 24). Must be run as a user with sudo access.

### Step 1: Clone the repository
```bash
git clone https://github.com/duffman188/fss-project.git
cd fss-project
```

### Step 2: Create network namespaces
```bash
chmod u+x setup_net enter
sudo ./setup_net
```

This creates three namespaces with the following IP layout:

| Node      | IP Address         |
|-----------|--------------------|
| ns_client | 10.0.0.1           |
| ns_mitm   | 10.0.0.2 / 10.0.1.1|
| ns_server | 10.0.1.2           |

> Run `sudo ./setup_net` again after every VM restart.

### Step 3: Open three terminals

**Terminal 1 — Server:**
```bash
sudo ./enter server
python3 server.py
```

**Terminal 2 — MITM:**
```bash
sudo ./enter mitm
python3 mitm.py
```

**Terminal 3 — Client:**
```bash
sudo ./enter client
python3 client.py
```

---

## Default Accounts

| Username | Password     |
|----------|--------------|
| alice    | password123  |
| bob      | letmein      |
| carol    | carol2026    |

---

## Running Attack Scripts

Replace `mitm.py` with any attack script in Terminal 2. For example, to demonstrate F-01 (credential eavesdropping):

```bash
# Terminal 2
sudo ./enter mitm
python3 mitm_F01.py
```

Then log in as alice in the client terminal and watch the MITM terminal print captured credentials.

For findings that use a `supplement_` script instead of a `mitm_` script, run that script directly in the appropriate shell without replacing mitm.py:

```bash
# F-09: run in MITM shell
python3 supplement_F09.py

# F-12: run in server shell
python3 supplement_F12.py
```

---

## Findings Summary

| ID   | Title                                      | Requirements | Severity |
|------|--------------------------------------------|--------------|----------|
| F-01 | Credentials transmitted in plaintext       | R1, R12      | Critical |
| F-02 | Upload content replaced in transit         | R5           | High     |
| F-03 | Session token stolen and reused            | R1, R8       | Critical |
| F-04 | Captured upload request replayed           | R4, R8       | High     |
| F-05 | Fake download response injected            | R6           | High     |
| F-06 | Path traversal via filename tampering      | R7           | High     |
| F-07 | Session token replaced with fixed value    | R8, R12      | High     |
| F-08 | Server response suppressed, client hangs   | R2, R10      | Medium   |
| F-09 | No rate limiting allows brute force        | R10          | High     |
| F-10 | Malformed input crashes server session     | R9           | Medium   |
| F-11 | Cross-user file access via token swap      | R1, R7       | Critical |
| F-12 | Passwords stored in plaintext              | R1, R12      | Critical |

Full details for each finding are in `findings_memo.txt`.

---

## Network Layout

```
[Client 10.0.0.1] <---> [MITM 10.0.0.2/10.0.1.1] <---> [Server 10.0.1.2]
     ns_client                  ns_mitm                      ns_server
```

All client-server traffic passes through the MITM node, making it trivial to observe, modify, replay, or suppress messages in the baseline system.

---

## Notes

- Do not use `python3 -m tls` or any TLS wrapper — the project requires application-layer security implementation (Stage 2).
- The baseline is intentionally insecure. Do not deploy it in any real environment.
- Attack scripts are kept finding-specific. Do not combine multiple attacks into one script.
