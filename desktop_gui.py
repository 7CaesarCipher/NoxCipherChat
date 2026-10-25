"""Tkinter desktop GUI for end-to-end encrypted chat and cipher tools."""
from __future__ import annotations

import json
import queue
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from tkinter import Tk, Text, StringVar, filedialog, messagebox, simpledialog, ttk
from tkinter.scrolledtext import ScrolledText
from urllib.parse import quote, urlparse
from uuid import uuid4

import websocket

from crypto_engine import (CLASSICAL_ALGORITHMS, HASH_ALGORITHMS,
                           MAX_TEXT_LENGTH, SECURE_ALGORITHMS, CryptoError,
                           classical_cipher, decrypt_payload, encrypt_payload,
                           generate_rsa_keys, hash_text, rsa_decrypt_text,
                           rsa_encrypt_text)


class NoxCipherGUI:
    def __init__(self) -> None:
        self.root = Tk()
        self.root.title("NoxCipher | Private Chat & Encryption Studio")
        self.root.geometry("1080x790")
        self.root.minsize(870, 680)
        self.root.configure(background="#eef2f8")
        self.events: queue.Queue = queue.Queue()
        self.socket: websocket.WebSocketApp | None = None
        self.connection_epoch = 0
        self.connected = False
        self.chat_room = ""
        self.chat_passphrase = ""
        self.chat_name = ""
        self.received_ids: set[str] = set()
        self._configure_styles()
        self._create_ui()
        self.root.after(80, self._drain_events)
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TFrame", background="#eef2f8")
        style.configure("TLabel", background="#eef2f8", foreground="#18243c", font=("Arial", 10))
        style.configure("TButton", padding=(12, 7), font=("Arial", 10))
        style.configure("TEntry", padding=6)
        style.configure("TCombobox", padding=5)
        style.configure("Title.TLabel", font=("Arial", 24, "bold"), foreground="#162d57")
        style.configure("Subtitle.TLabel", font=("Arial", 10), foreground="#52617b")
        style.configure("Section.TLabel", font=("Arial", 11, "bold"), foreground="#193c78")
        style.configure("Warn.TLabel", font=("Arial", 9), foreground="#9b5f10")
        style.configure("TNotebook", background="#eef2f8", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(16, 11), font=("Arial", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "#dce8fc")])

    def _create_ui(self) -> None:
        outer = ttk.Frame(self.root, padding=18)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="NOXCIPHER", style="Title.TLabel").pack(anchor="w")
        ttk.Label(outer, text="End-to-end encrypted chat  •  Secure text  •  RSA hybrid  •  Cipher laboratory", style="Subtitle.TLabel").pack(anchor="w", pady=(0, 13))
        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill="both", expand=True)
        self.tab_chat = ttk.Frame(self.tabs, padding=13)
        self.tab_secure = ttk.Frame(self.tabs, padding=13)
        self.tab_rsa = ttk.Frame(self.tabs, padding=13)
        self.tab_classical = ttk.Frame(self.tabs, padding=13)
        self.tab_hashes = ttk.Frame(self.tabs, padding=13)
        self.tabs.add(self.tab_chat, text="Encrypted Chat")
        self.tabs.add(self.tab_secure, text="Encrypt / Decrypt")
        self.tabs.add(self.tab_rsa, text="RSA Hybrid")
        self.tabs.add(self.tab_classical, text="Classical Ciphers")
        self.tabs.add(self.tab_hashes, text="Hash Tools")
        self._build_chat()
        self._build_secure()
        self._build_rsa()
        self._build_classical()
        self._build_hashes()
        ttk.Label(outer, text="Private chat uses authenticated encryption locally. Shared-passphrase rooms are a demonstration, not an identity-verified messenger.", style="Subtitle.TLabel").pack(anchor="w", pady=(12, 0))

    @staticmethod
    def _label_entry(parent, row: int, column: int, label: str, variable: StringVar,
                     *, show: str | None = None, width: int = 24) -> ttk.Entry:
        ttk.Label(parent, text=label).grid(row=row, column=column, sticky="w", pady=(5, 2))
        entry = ttk.Entry(parent, textvariable=variable, width=width, show=show or "")
        entry.grid(row=row + 1, column=column, sticky="ew", padx=(0, 12), pady=(0, 5))
        return entry

    @staticmethod
    def _text(parent, height: int = 7, readonly: bool = False) -> ScrolledText:
        field = ScrolledText(parent, wrap="word", height=height, font=("Consolas", 10),
                             padx=10, pady=9, relief="solid", borderwidth=1,
                             foreground="#16243d", background="#ffffff")
        if readonly:
            field.configure(state="disabled")
        return field

    @staticmethod
    def _value(field: Text) -> str:
        return field.get("1.0", "end-1c")

    @staticmethod
    def _set(field: Text, value: str) -> None:
        field.configure(state="normal")
        field.delete("1.0", "end")
        field.insert("1.0", value)

    def _error(self, title: str, exc: Exception) -> None:
        messagebox.showerror(title, str(exc), parent=self.root)

    def _copy(self, field: Text) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(self._value(field))
        self.root.update_idletasks()

    def _paste(self, field: Text) -> None:
        try:
            self._set(field, self.root.clipboard_get())
        except Exception:
            pass

    def _build_chat(self) -> None:
        frame = self.tab_chat
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(3, weight=1)
        settings = ttk.LabelFrame(frame, text="Room connection (same room + passphrase on both clients)", padding=10)
        settings.grid(row=0, column=0, sticky="ew")
        for c in range(4):
            settings.columnconfigure(c, weight=1)
        self.server_var = StringVar(value="ws://127.0.0.1:8765")
        self.room_var = StringVar(value="demo-room")
        self.name_var = StringVar(value="User1")
        self.room_pass_var = StringVar()
        self.algorithm_var = StringVar(value="AES-256-GCM")
        self._label_entry(settings, 0, 0, "Relay URL", self.server_var, width=28)
        self._label_entry(settings, 0, 1, "Room ID", self.room_var)
        self._label_entry(settings, 0, 2, "Display name", self.name_var)
        self._label_entry(settings, 0, 3, "Shared passphrase", self.room_pass_var, show="•")
        ttk.Label(settings, text="Algorithm for outgoing messages").grid(row=2, column=0, sticky="w", pady=(6, 2))
        ttk.Combobox(settings, textvariable=self.algorithm_var, values=SECURE_ALGORITHMS,
                     state="readonly", width=24).grid(row=3, column=0, sticky="ew", padx=(0, 12))
        buttons = ttk.Frame(settings)
        buttons.grid(row=3, column=1, columnspan=3, sticky="w")
        self.connect_button = ttk.Button(buttons, text="Connect", command=self._connect)
        self.connect_button.pack(side="left", padx=(0, 8))
        self.disconnect_button = ttk.Button(buttons, text="Disconnect", command=self._disconnect, state="disabled")
        self.disconnect_button.pack(side="left")
        self.status_var = StringVar(value="Disconnected • run the relay server and open two app windows")
        ttk.Label(frame, textvariable=self.status_var, style="Subtitle.TLabel").grid(row=1, column=0, sticky="w", pady=8)
        ttk.Label(frame, text="Room messages", style="Section.TLabel").grid(row=2, column=0, sticky="w", pady=(4, 4))
        self.transcript = self._text(frame, 16, readonly=True)
        self.transcript.grid(row=3, column=0, sticky="nsew")
        self.transcript.tag_configure("system", foreground="#62728b")
        self.transcript.tag_configure("self", foreground="#1768ae")
        self.transcript.tag_configure("other", foreground="#17233b")
        self.transcript.tag_configure("error", foreground="#a24532")
        ttk.Label(frame, text="Compose message (Ctrl+Enter to send)", style="Section.TLabel").grid(row=4, column=0, sticky="w", pady=(10, 4))
        entry_frame = ttk.Frame(frame)
        entry_frame.grid(row=5, column=0, sticky="ew")
        entry_frame.columnconfigure(0, weight=1)
        self.chat_compose = self._text(entry_frame, 3)
        self.chat_compose.grid(row=0, column=0, sticky="ew")
        self.chat_compose.bind("<Control-Return>", self._send_from_shortcut)
        self.send_button = ttk.Button(entry_frame, text="Send encrypted", command=self._send, state="disabled")
        self.send_button.grid(row=0, column=1, padx=(10, 0), sticky="ns")

    def _log(self, text: str, category: str = "system") -> None:
        self.transcript.configure(state="normal")
        self.transcript.insert("end", text + "\n", category)
        self.transcript.see("end")
        self.transcript.configure(state="disabled")

    def _connect(self) -> None:
        if self.socket is not None:
            return
        server = self.server_var.get().strip().rstrip("/")
        room = self.room_var.get().strip()
        name = self.name_var.get().strip()
        passphrase = self.room_pass_var.get()
        try:
            parsed = urlparse(server)
            if parsed.scheme not in ("ws", "wss") or not parsed.netloc or parsed.path not in ("", "/"):
                raise CryptoError("Relay URL must be a base ws:// or wss:// URL, with no path.")
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise CryptoError("Relay URL must not contain credentials or query parameters.")
            if parsed.scheme == "ws" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
                raise CryptoError("Use wss:// for remote relays. Plain ws:// is only allowed on this computer.")
            if not re.fullmatch(r"[A-Za-z0-9_-]{3,48}", room):
                raise CryptoError("Room ID must contain 3–48 letters, digits, hyphens, or underscores.")
            if not (1 <= len(name) <= 32):
                raise CryptoError("Display name must be 1–32 characters.")
            if len(passphrase) < 12:
                raise CryptoError("Shared passphrase must be at least 12 characters. Prefer a long random phrase.")
        except Exception as exc:
            self._error("Cannot connect", exc)
            return
        self.connection_epoch += 1
        epoch = self.connection_epoch
        self.chat_room, self.chat_passphrase, self.chat_name = room, passphrase, name
        self.received_ids.clear()
        self.status_var.set("Connecting…")
        self.connect_button.configure(state="disabled")
        self.disconnect_button.configure(state="normal")
        url = server + "/ws/" + quote(room, safe="")

        def on_open(_ws):
            self.events.put((epoch, "open", None))

        def on_message(_ws, raw):
            try:
                obj = json.loads(raw)
                if obj.get("type") == "status":
                    self.events.put((epoch, "info", obj.get("message", "Connected.")))
                elif obj.get("type") == "error":
                    self.events.put((epoch, "error", obj.get("message", "Relay error")))
                elif obj.get("type") == "message":
                    packet = obj.get("data")
                    data = decrypt_payload(packet, passphrase, f"room:{room}")
                    if data.get("kind") != "chat" or not isinstance(data.get("message"), str):
                        raise CryptoError("Packet does not contain a chat message.")
                    if len(data["message"]) > MAX_TEXT_LENGTH:
                        raise CryptoError("Message exceeds the length limit.")
                    self.events.put((epoch, "chat", (data, packet.get("algorithm", "Unknown"))))
            except (ValueError, TypeError, AttributeError, UnicodeError) as exc:
                self.events.put((epoch, "error", f"Could not read a message: {exc}"))

        def on_error(_ws, err):
            self.events.put((epoch, "error", f"Connection error: {err}"))

        def on_close(_ws, _code, _reason):
            self.events.put((epoch, "closed", None))

        self.socket = websocket.WebSocketApp(url, on_open=on_open, on_message=on_message,
                                               on_error=on_error, on_close=on_close)
        threading.Thread(target=self.socket.run_forever,
                         kwargs={"ping_interval": 25, "ping_timeout": 10}, daemon=True).start()

    def _drain_events(self) -> None:
        try:
            while True:
                epoch, kind, data = self.events.get_nowait()
                if epoch != self.connection_epoch:
                    continue
                if kind == "open":
                    self.connected = True
                    self.status_var.set("Connected • messages encrypted before leaving this app")
                    self.send_button.configure(state="normal")
                elif kind == "info":
                    self._log(str(data))
                elif kind == "error":
                    self._log(str(data), "error")
                elif kind == "chat":
                    payload, algorithm = data
                    message_id = payload.get("id")
                    if not isinstance(message_id, str) or message_id in self.received_ids:
                        continue
                    self.received_ids.add(message_id)
                    if len(self.received_ids) > 10000:
                        self.received_ids.clear()
                        self.received_ids.add(message_id)
                    name = str(payload.get("sender", "Peer"))[:32]
                    stamp = str(payload.get("time", ""))[:35]
                    category = "self" if name == self.chat_name else "other"
                    self._log(f"[{stamp}] {name}  ({algorithm})\n{payload['message']}\n", category)
                elif kind == "closed":
                    self.status_var.set("Disconnected")
                    self.connected = False
                    self.socket = None
                    self.chat_passphrase = ""
                    self.connect_button.configure(state="normal")
                    self.disconnect_button.configure(state="disabled")
                    self.send_button.configure(state="disabled")
        except queue.Empty:
            pass
        self.root.after(80, self._drain_events)

    def _disconnect(self) -> None:
        self.connection_epoch += 1
        sock, self.socket = self.socket, None
        self.connected = False
        self.chat_passphrase = ""
        self.status_var.set("Disconnected")
        self.connect_button.configure(state="normal")
        self.disconnect_button.configure(state="disabled")
        self.send_button.configure(state="disabled")
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    def _send_from_shortcut(self, _event):
        self._send()
        return "break"

    def _send(self) -> None:
        if not self.connected or self.socket is None:
            return
        message = self._value(self.chat_compose).strip()
        if not message:
            return
        if len(message) > MAX_TEXT_LENGTH:
            self._error("Message too long", CryptoError("Maximum message length is 5000 characters."))
            return
        try:
            packet = encrypt_payload({"kind": "chat", "id": str(uuid4()),
                                      "sender": self.chat_name, "message": message,
                                      "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")},
                                     self.chat_passphrase, self.algorithm_var.get(), f"room:{self.chat_room}")
            self.socket.send(json.dumps({"type": "message", "data": packet}, separators=(",", ":")))
            self._set(self.chat_compose, "")
        except Exception as exc:
            self._error("Send failed", exc)

    def _build_secure(self) -> None:
        frame = self.tab_secure
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(3, weight=1)
        frame.rowconfigure(6, weight=1)
        ttk.Label(frame, text="Authenticated symmetric encryption", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        controls = ttk.Frame(frame)
        controls.grid(row=1, column=0, sticky="ew", pady=8)
        self.text_algorithm_var = StringVar(value="AES-256-GCM")
        self.text_secret_var = StringVar()
        ttk.Label(controls, text="Algorithm").pack(side="left")
        ttk.Combobox(controls, textvariable=self.text_algorithm_var, values=SECURE_ALGORITHMS,
                     state="readonly", width=21).pack(side="left", padx=(8, 22))
        ttk.Label(controls, text="Passphrase (12+ characters)").pack(side="left")
        ttk.Entry(controls, textvariable=self.text_secret_var, show="•", width=35).pack(side="left", padx=8)
        ttk.Label(frame, text="Input text OR encrypted JSON packet").grid(row=2, column=0, sticky="w")
        self.secure_input = self._text(frame, height=8)
        self.secure_input.grid(row=3, column=0, sticky="nsew", pady=(4, 8))
        action = ttk.Frame(frame)
        action.grid(row=4, column=0, sticky="w", pady=(0, 8))
        ttk.Button(action, text="Encrypt", command=lambda: self._secure_action(False)).pack(side="left", padx=(0, 8))
        ttk.Button(action, text="Decrypt", command=lambda: self._secure_action(True)).pack(side="left", padx=(0, 8))
        ttk.Button(action, text="Paste input", command=lambda: self._paste(self.secure_input)).pack(side="left", padx=(0, 8))
        ttk.Button(action, text="Copy result", command=lambda: self._copy(self.secure_output)).pack(side="left", padx=(0, 8))
        ttk.Button(action, text="Result → Input", command=lambda: self._set(self.secure_input, self._value(self.secure_output))).pack(side="left")
        ttk.Label(frame, text="Result", style="Section.TLabel").grid(row=5, column=0, sticky="w")
        self.secure_output = self._text(frame, height=9)
        self.secure_output.grid(row=6, column=0, sticky="nsew", pady=(4, 5))
        ttk.Label(frame, text="JSON packets include an algorithm, random salt and nonce; the passphrase is never embedded in the output.", style="Subtitle.TLabel").grid(row=7, column=0, sticky="w")

    def _secure_action(self, decrypt: bool) -> None:
        try:
            text = self._value(self.secure_input)
            secret = self.text_secret_var.get()
            if decrypt:
                packet = json.loads(text)
                data = decrypt_payload(packet, secret, "playground")
                if data.get("kind") != "note" or not isinstance(data.get("text"), str):
                    raise CryptoError("Not a secure-text packet.")
                self._set(self.secure_output, data["text"])
            else:
                if len(text) > MAX_TEXT_LENGTH:
                    raise CryptoError("Maximum text length is 5000 characters.")
                packet = encrypt_payload({"kind": "note", "text": text}, secret,
                                         self.text_algorithm_var.get(), "playground")
                self._set(self.secure_output, json.dumps(packet, indent=2, ensure_ascii=False))
        except (CryptoError, ValueError, TypeError) as exc:
            self._error("Decryption failed" if decrypt else "Encryption failed", exc)

    def _build_rsa(self) -> None:
        frame = self.tab_rsa
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(3, weight=1)
        frame.rowconfigure(6, weight=1)
        ttk.Label(frame, text="RSA-OAEP (SHA-256) + AES-256-GCM hybrid encryption", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        options = ttk.Frame(frame)
        options.grid(row=1, column=0, sticky="ew", pady=8)
        options.columnconfigure(1, weight=1)
        self.public_file = StringVar()
        self.private_file = StringVar()
        self.rsa_password = StringVar()
        ttk.Label(options, text="Public key PEM").grid(row=0, column=0, sticky="w")
        ttk.Entry(options, textvariable=self.public_file).grid(row=0, column=1, sticky="ew", padx=8, pady=3)
        ttk.Button(options, text="Browse", command=lambda: self._choose_key(self.public_file)).grid(row=0, column=2)
        ttk.Label(options, text="Private key PEM").grid(row=1, column=0, sticky="w")
        ttk.Entry(options, textvariable=self.private_file).grid(row=1, column=1, sticky="ew", padx=8, pady=3)
        ttk.Button(options, text="Browse", command=lambda: self._choose_key(self.private_file)).grid(row=1, column=2)
        ttk.Label(options, text="Private key password").grid(row=2, column=0, sticky="w")
        ttk.Entry(options, textvariable=self.rsa_password, show="•").grid(row=2, column=1, sticky="ew", padx=8, pady=3)
        ttk.Button(options, text="Generate RSA-3072 keys", command=self._generate_keys).grid(row=2, column=2, padx=(5, 0))
        ttk.Label(frame, text="Input text OR RSA encrypted JSON packet").grid(row=2, column=0, sticky="w")
        self.rsa_input = self._text(frame, 6)
        self.rsa_input.grid(row=3, column=0, sticky="nsew", pady=(4, 7))
        actions = ttk.Frame(frame)
        actions.grid(row=4, column=0, sticky="w", pady=(0, 8))
        ttk.Button(actions, text="Encrypt using public key", command=lambda: self._rsa_action(False)).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Decrypt using private key", command=lambda: self._rsa_action(True)).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Copy result", command=lambda: self._copy(self.rsa_output)).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Result → Input", command=lambda: self._set(self.rsa_input, self._value(self.rsa_output))).pack(side="left")
        ttk.Label(frame, text="Result", style="Section.TLabel").grid(row=5, column=0, sticky="w")
        self.rsa_output = self._text(frame, 7)
        self.rsa_output.grid(row=6, column=0, sticky="nsew", pady=(4, 5))
        ttk.Label(frame, text="Share your public key, NEVER your private key or its password. RSA hybrid works in this tool; room chat uses shared passphrases.", style="Warn.TLabel").grid(row=7, column=0, sticky="w")

    def _choose_key(self, variable: StringVar) -> None:
        path = filedialog.askopenfilename(parent=self.root, filetypes=[("PEM key", "*.pem"), ("All files", "*")])
        if path:
            variable.set(path)

    def _generate_keys(self) -> None:
        directory = filedialog.askdirectory(parent=self.root, title="Choose an empty folder for your RSA keypair")
        if not directory:
            return
        password = simpledialog.askstring("Protect your private key", "Enter a private-key password (12+ characters):", show="•", parent=self.root)
        if password is None:
            return
        try:
            private, public = generate_rsa_keys(directory, password)
            self.private_file.set(private)
            self.public_file.set(public)
            self.rsa_password.set(password)
            messagebox.showinfo("RSA keys created", f"Public key:\n{public}\n\nPrivate key:\n{private}\n\nKeep the private file and password secret.", parent=self.root)
        except Exception as exc:
            self._error("Key generation failed", exc)

    def _rsa_action(self, decrypt: bool) -> None:
        try:
            text = self._value(self.rsa_input)
            if decrypt:
                path = Path(self.private_file.get())
                result = rsa_decrypt_text(json.loads(text), path.read_bytes(), self.rsa_password.get())
            else:
                path = Path(self.public_file.get())
                packet = rsa_encrypt_text(text, path.read_bytes())
                result = json.dumps(packet, indent=2)
            self._set(self.rsa_output, result)
        except (CryptoError, OSError, ValueError, TypeError) as exc:
            self._error("RSA decryption failed" if decrypt else "RSA encryption failed", exc)

    def _build_classical(self) -> None:
        frame = self.tab_classical
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(3, weight=1)
        frame.rowconfigure(6, weight=1)
        ttk.Label(frame, text="Classical cipher laboratory", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(frame, text="Educational only — Caesar, Vigenere, ROT13 and Atbash do NOT provide secure messaging.", style="Warn.TLabel").grid(row=1, column=0, sticky="w", pady=7)
        choices = ttk.Frame(frame)
        choices.grid(row=2, column=0, sticky="w", pady=7)
        self.classical_algorithm_var = StringVar(value="Caesar")
        self.classical_key_var = StringVar(value="3")
        ttk.Label(choices, text="Cipher").pack(side="left")
        ttk.Combobox(choices, values=CLASSICAL_ALGORITHMS, textvariable=self.classical_algorithm_var,
                     state="readonly", width=18).pack(side="left", padx=(8, 22))
        ttk.Label(choices, text="Shift / key").pack(side="left")
        ttk.Entry(choices, textvariable=self.classical_key_var, width=28).pack(side="left", padx=8)
        self.classical_input = self._text(frame, height=9)
        self.classical_input.grid(row=3, column=0, sticky="nsew", pady=(7, 9))
        row = ttk.Frame(frame)
        row.grid(row=4, column=0, sticky="w", pady=(0, 7))
        ttk.Button(row, text="Encode", command=lambda: self._classical_action(False)).pack(side="left", padx=(0, 8))
        ttk.Button(row, text="Decode", command=lambda: self._classical_action(True)).pack(side="left", padx=(0, 8))
        ttk.Button(row, text="Copy result", command=lambda: self._copy(self.classical_output)).pack(side="left")
        ttk.Label(frame, text="Result", style="Section.TLabel").grid(row=5, column=0, sticky="w")
        self.classical_output = self._text(frame, height=9)
        self.classical_output.grid(row=6, column=0, sticky="nsew")

    def _classical_action(self, decrypt: bool) -> None:
        try:
            result = classical_cipher(self._value(self.classical_input), self.classical_algorithm_var.get(),
                                      self.classical_key_var.get(), decrypt=decrypt)
            self._set(self.classical_output, result)
        except CryptoError as exc:
            self._error("Classical cipher error", exc)

    def _build_hashes(self) -> None:
        frame = self.tab_hashes
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(3, weight=1)
        frame.rowconfigure(6, weight=1)
        ttk.Label(frame, text="Cryptographic hashing (one-way, not encryption)", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(frame, text="Hashes cannot be decrypted. Use a password-hashing KDF for storing passwords, not plain SHA-256.", style="Subtitle.TLabel").grid(row=1, column=0, sticky="w", pady=(6, 13))
        settings = ttk.Frame(frame)
        settings.grid(row=2, column=0, sticky="w")
        self.hash_algorithm_var = StringVar(value="SHA-256")
        ttk.Label(settings, text="Algorithm").pack(side="left")
        ttk.Combobox(settings, textvariable=self.hash_algorithm_var, values=HASH_ALGORITHMS,
                     state="readonly", width=20).pack(side="left", padx=(8, 20))
        ttk.Button(settings, text="Calculate hash", command=self._hash_action).pack(side="left", padx=(0, 8))
        ttk.Button(settings, text="Copy hash", command=lambda: self._copy(self.hash_output)).pack(side="left")
        self.hash_input = self._text(frame, height=9)
        self.hash_input.grid(row=3, column=0, sticky="nsew", pady=(12, 9))
        ttk.Label(frame, text="Hash digest (hexadecimal)", style="Section.TLabel").grid(row=5, column=0, sticky="w")
        self.hash_output = self._text(frame, height=8)
        self.hash_output.grid(row=6, column=0, sticky="nsew", pady=(5, 0))

    def _hash_action(self) -> None:
        try:
            self._set(self.hash_output, hash_text(self._value(self.hash_input), self.hash_algorithm_var.get()))
        except CryptoError as exc:
            self._error("Hashing error", exc)

    def _close(self) -> None:
        self._disconnect()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


if __name__ == "__main__":
    NoxCipherGUI().run()
