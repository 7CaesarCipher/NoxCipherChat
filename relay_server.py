"""Stateless encrypted-message relay. Never receives passphrases or plaintext."""
from __future__ import annotations

import asyncio
import json
import re
import time
from collections import defaultdict, deque

from crypto_engine import SECURE_ALGORITHMS

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

app = FastAPI(title="NoxCipher Encrypted Chat Relay", version="1.0.0")
_rooms: dict[str, set[WebSocket]] = defaultdict(set)
_lock = asyncio.Lock()
ROOM_RE = re.compile(r"^[A-Za-z0-9_-]{3,48}$")
MAX_CONNECTIONS_PER_ROOM = 24
MAX_FRAME_SIZE = 24000
MAX_MESSAGES_PER_10_SECONDS = 15


@app.get("/health")
async def health():
    return {"status": "ok", "service": "noxcipher-relay", "message_storage": "none"}


@app.websocket("/ws/{room}")
async def relay(websocket: WebSocket, room: str):
    if not ROOM_RE.fullmatch(room):
        await websocket.close(code=1008, reason="Invalid room identifier")
        return
    async with _lock:
        if len(_rooms[room]) >= MAX_CONNECTIONS_PER_ROOM:
            await websocket.close(code=1008, reason="Room is full")
            return
        await websocket.accept()
        _rooms[room].add(websocket)
        count = len(_rooms[room])
    await websocket.send_json({"type": "status", "message": f"Connected to room {room} ({count} participant(s))."})
    recent_messages: deque[float] = deque()
    try:
        while True:
            raw = await websocket.receive_text()
            if len(raw.encode("utf-8")) > MAX_FRAME_SIZE:
                await websocket.send_json({"type": "error", "message": "Packet too large."})
                continue
            now = time.monotonic()
            while recent_messages and now - recent_messages[0] > 10:
                recent_messages.popleft()
            if len(recent_messages) >= MAX_MESSAGES_PER_10_SECONDS:
                await websocket.send_json({"type": "error", "message": "Rate limit: try again shortly."})
                continue
            recent_messages.append(now)
            try:
                body = json.loads(raw)
                packet = body.get("data") if isinstance(body, dict) and body.get("type") == "message" else None
                if not isinstance(packet, dict) or type(packet.get("version")) is not int or packet["version"] != 1:
                    raise ValueError("Invalid packet")
                algorithm = packet.get("algorithm")
                if algorithm not in SECURE_ALGORITHMS:
                    raise ValueError("Unknown algorithm")
                expected_fields = {"version", "algorithm", "salt", "ciphertext"}
                if algorithm != "Fernet":
                    expected_fields.add("nonce")
                # Strict allowlist: never forward extra data fields, e.g. accidental plaintext.
                if set(packet) != expected_fields:
                    raise ValueError("Unexpected message fields")
                if any(not isinstance(packet.get(field), str) for field in expected_fields - {"version", "algorithm"}):
                    raise ValueError("Invalid packet")
                if len(packet["salt"]) > 128 or len(packet["ciphertext"]) > MAX_FRAME_SIZE:
                    raise ValueError("Packet field is too large")
                if algorithm != "Fernet" and len(packet["nonce"]) > 128:
                    raise ValueError("Invalid nonce")
                # Relay transmits opaque ciphertext; it never decrypts messages.
            except (ValueError, TypeError):
                await websocket.send_json({"type": "error", "message": "Invalid encrypted-message envelope."})
                continue
            outgoing = {"type": "message", "data": packet}
            async with _lock:
                peers = list(_rooms.get(room, ()))
            for peer in peers:
                try:
                    await peer.send_json(outgoing)
                except (RuntimeError, WebSocketDisconnect, OSError):
                    pass
    except WebSocketDisconnect:
        pass
    except (RuntimeError, OSError):
        pass
    finally:
        async with _lock:
            _rooms[room].discard(websocket)
            if not _rooms[room]:
                _rooms.pop(room, None)
