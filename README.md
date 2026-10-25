# NoxCipher — encrypted chat & encryption GUI

A runnable **cross-platform Python desktop GUI** with a local-only cryptography engine and a small WebSocket relay. Open two GUI windows, join the same room with the same long passphrase, and send encrypted messages. The relay forwards encrypted packets; it cannot read chat content or receive passphrases.

## Algorithms included

| Tool | Algorithms | Purpose |
| --- | --- | --- |
| Encrypted Chat | AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305, Fernet | Authenticated symmetric encryption using a shared passphrase |
| Encrypt / Decrypt | Same four algorithms | Encrypt arbitrary text into portable JSON packets and decrypt them |
| RSA Hybrid | RSA-OAEP-SHA256 + AES-256-GCM | Public-key encryption for sharing text with someone who has a private key |
| Classical Ciphers | Caesar, Vigenere, ROT13, Atbash | Educational demonstrations only — insecure |
| Hash Tools | SHA-256, SHA3-256, SHA-512, BLAKE2b-256 | One-way checksums / digest demonstrations; not decryptable |

**Not literally every algorithm:** there are hundreds of cryptographic constructions. DES, 3DES, RC4, ECB, and other obsolete designs are deliberately excluded from private chat.

## Requirements

- Python **3.11+** with Tkinter installed (Python.org's macOS/Windows installer normally includes Tkinter).
- `pip` and a terminal.
- A free TCP port **8765** on your machine, rather than ports 8000/5432 used by other development apps.

## One-click local launch (recommended)

- **Windows:** double-click `start_windows.bat` (Python 3.11+ installed).
- **macOS:** run `./start_mac.command` from Terminal (or double-click it if macOS allows it).
- The launcher creates an isolated `.venv` if necessary, installs packages, runs a local relay automatically, and opens the GUI. To open a **second chat window**, run `python desktop_gui.py` in the virtual environment. The local relay is owned by the first launcher window and stops when that first window closes.
- For advanced use, or to keep the server running independently, follow the manual start instructions below.

## macOS / Linux quick start

Open a terminal in the `NoxCipher_Chat` folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Start the relay in **terminal 1**:

```bash
python -m uvicorn relay_server:app --host 127.0.0.1 --port 8765 --no-access-log
```

Start two GUI clients in **terminal 2 and terminal 3**:

```bash
python desktop_gui.py
```

If `python3 -m tkinter` fails, install a Python build with Tk support. A local relay status endpoint is at http://127.0.0.1:8765/health.

### Homebrew Python 3.14 + Rosetta (Apple Silicon)

If Homebrew says `Cannot install under Rosetta 2 in ARM default prefix (/opt/homebrew)`, run:

```bash
arch -arm64 /opt/homebrew/bin/brew install python-tk@3.14
arch -arm64 .venv/bin/python -m tkinter
```

If pip crashes in `pip/_vendor/truststore/_macos.py` with
`ValueError: invalid literal for int() with base 10: ''`,
`platform.mac_ver()[0]` is empty on that Python/macOS combination. Use pip's supported
certificate handling fallback, which **still verifies TLS**:

```bash
arch -arm64 .venv/bin/python -m pip install \
  --use-deprecated=legacy-certs --disable-pip-version-check -r requirements.txt
arch -arm64 .venv/bin/python run_local.py
```

The updated `start_mac.command` runs these dependency-install options automatically and
reports if Tkinter is missing. The fix does not require upgrading pip or disabling
TLS verification. If the GUI still cannot launch, verify the interpreter's version output:

```bash
arch -arm64 .venv/bin/python -c 'import platform; print(repr(platform.mac_ver()[0]))'
```


## Windows quick start (no PowerShell activation required)

Run in **PowerShell** from the project folder:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

In one PowerShell window:

```powershell
.\.venv\Scripts\python.exe -m uvicorn relay_server:app --host 127.0.0.1 --port 8765 --no-access-log
```

In two other PowerShell windows:

```powershell
.\.venv\Scripts\python.exe desktop_gui.py
```

This avoids Windows' blocked `Activate.ps1` execution policy.

## Chat walkthrough

1. In both desktop clients, enter relay URL `ws://127.0.0.1:8765`, the **same** room ID (e.g. `research_chat`), and the **same** strong 12+ character passphrase.
2. Choose different display names (e.g. Alice and Bob), then click **Connect**.
3. Alice chooses **AES-256-GCM**, types a message, and clicks **Send encrypted**. Bob receives and decrypts it locally.
4. Bob may switch his outgoing algorithm to **ChaCha20-Poly1305**, **AES-128-GCM**, or **Fernet**; Alice automatically reads the algorithm listed in Bob's packet and decrypts with the shared passphrase.
5. Messages are **not saved**. Closing both applications loses the chat history. The server retains no history and new participants cannot see previous messages.

The algorithm can vary *per message*. The server does not know usernames or plaintext because both are inside encrypted data. However, the server can see the room ID, chosen algorithm, ciphertext size, and connections.

## Encrypt / Decrypt standalone text

1. Open **Encrypt / Decrypt**, choose a symmetric algorithm, type a 12+ character passphrase and plaintext, then **Encrypt**.
2. Copy the JSON packet from Result. On the other device/instance, paste into Input, enter the same passphrase, then **Decrypt**.
3. The JSON packet contains the required metadata (salt/nonce/algorithm) but **never the secret**.
4. Text packets are context-bound to the standalone tool and cannot be injected into room chats.

## RSA hybrid public/private tool

1. Open **RSA Hybrid** and click **Generate RSA-3072 keys**. Choose a folder and enter a strong password protecting your **private** PEM.
2. Share **only** `noxcipher_public.pem` with anyone who wants to encrypt a message to you.
3. Encryptors select your public key in the GUI, then **Encrypt using public key** to get a JSON packet.
4. You select your private PEM, enter the private-key password, paste the encrypted JSON packet, then click **Decrypt using private key**.
5. Internally, every RSA hybrid message uses a fresh AES-256-GCM session key wrapped by RSA-OAEP-SHA256. RSA is not used to directly encrypt lengthy text.

RSA hybrid works in the **RSA Hybrid** tool, not in the shared-passphrase chat room. Private PEM files are excluded by `.gitignore`; don't upload or share them.

## Docker relay option

If Docker is already installed:

```bash
docker compose up --build -d
```

Start GUI separately on your host (`python desktop_gui.py`). Compose exposes the relay only on `127.0.0.1:8765`. Stop it with `docker compose down`. No PostgreSQL/database is needed.

## Remote chat / security limits

- For two machines on different networks, deploy the relay behind a **TLS reverse proxy** and configure the clients with `wss://your-host.example`. The GUI deliberately refuses insecure `ws://` to non-local hosts. Do not expose the provided Docker relay directly to the Internet without adding authentication, TLS and operational protections.
- Encryption and decryption happen on **endpoints**. Passphrases and RSA private keys are never transmitted to the relay. Unique random salts plus **scrypt** derive per-message keys; AES-GCM and ChaCha20-Poly1305 authenticate messages, and Fernet authenticates its token.
- **This is a demonstration, not an audited production messenger.** A shared passphrase has no individual identity verification, forward secrecy, or authenticated key exchange. Someone who learns it can impersonate participants and potentially decrypt captured packets; offline passphrase guessing remains possible. Use long random passphrases distributed through a trusted channel.
- The relay can observe metadata, drop/replay encrypted packets, and identify room IDs. Clients discard repeated message IDs only within a session. Room display names can be spoofed by any participant possessing the shared secret.
- Ciphertext persists only in transit/in-memory. The relay has no database, storage, or history endpoint. Client GUI plaintext stays in process memory and remains visible on screen until closed.
- Hash functions are **one-way** and cannot be decrypted. Classical ciphers do not secure conversations.

## Run tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

## Files

- `run_local.py`, `start_mac.command`, `start_windows.bat`: local relay + GUI starters
- `desktop_gui.py`: Tkinter desktop interface and WebSocket chat client
- `crypto_engine.py`: symmetric encryption, RSA hybrid, classical ciphers and hashes
- `relay_server.py`: FastAPI WebSocket ciphertext relay
- `tests/`: cryptographic and relay end-to-end tests
- `compose.yaml`, `Dockerfile`: optional relay deployment

License: educational starter project; review and security-hardening required for real deployments.
