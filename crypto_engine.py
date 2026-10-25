"""Local cryptography for NoxCipher Chat. Encryption keys never go to the relay."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


SECURE_ALGORITHMS = ("AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305", "Fernet")
CLASSICAL_ALGORITHMS = ("Caesar", "Vigenere", "ROT13", "Atbash")
HASH_ALGORITHMS = ("SHA-256", "SHA3-256", "SHA-512", "BLAKE2b-256")
HYBRID_ALGORITHM = "RSA-OAEP-SHA256+AES-256-GCM"
MAX_TEXT_LENGTH = 5000
MAX_PACKET_LENGTH = 24000
VERSION = 1


class CryptoError(ValueError):
    """User-safe encryption/decryption error."""


def _encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _decode(value: Any, name: str, max_encoded: int = MAX_PACKET_LENGTH) -> bytes:
    if not isinstance(value, str) or len(value) > max_encoded:
        raise CryptoError(f"Invalid {name} field.")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, Exception) as exc:
        raise CryptoError(f"Invalid {name} base64.") from exc


def _derive_key(passphrase: str, salt: bytes, algorithm: str) -> bytes:
    if not isinstance(passphrase, str) or len(passphrase) < 12:
        raise CryptoError("Passphrase must contain at least 12 characters.")
    key_length = 16 if algorithm == "AES-128-GCM" else 32
    return Scrypt(salt=salt, length=key_length, n=2**14, r=8, p=1).derive(passphrase.encode("utf-8"))


def _aad(algorithm: str, context: str) -> bytes:
    return f"noxcipher-v1|{algorithm}|{context}".encode("utf-8")


def encrypt_payload(data: dict[str, Any], passphrase: str, algorithm: str, context: str) -> dict[str, Any]:
    """Authenticated encryption of a JSON object using a per-message random salt."""
    if algorithm not in SECURE_ALGORITHMS:
        raise CryptoError("Unsupported secure algorithm.")
    if not isinstance(context, str) or not context or len(context) > 100:
        raise CryptoError("Invalid encryption context.")
    plaintext = json.dumps({"context": context, "data": data}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(plaintext) > 16000:
        raise CryptoError("Message exceeds the size limit.")
    salt = os.urandom(16)
    key = _derive_key(passphrase, salt, algorithm)
    if algorithm == "Fernet":
        return {"version": VERSION, "algorithm": algorithm, "salt": _encode(salt),
                "ciphertext": Fernet(base64.urlsafe_b64encode(key)).encrypt(plaintext).decode("ascii")}
    nonce = os.urandom(12)
    cipher = AESGCM(key) if algorithm.startswith("AES-") else ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, plaintext, _aad(algorithm, context))
    return {"version": VERSION, "algorithm": algorithm, "salt": _encode(salt),
            "nonce": _encode(nonce), "ciphertext": _encode(ciphertext)}


def decrypt_payload(envelope: dict[str, Any], passphrase: str, context: str) -> dict[str, Any]:
    """Decrypt a packet and authenticate its context (room or playground)."""
    if not isinstance(envelope, dict) or envelope.get("version") != VERSION:
        raise CryptoError("Unrecognized or invalid packet version.")
    algorithm = envelope.get("algorithm")
    if algorithm not in SECURE_ALGORITHMS:
        raise CryptoError("Unsupported secure algorithm.")
    salt = _decode(envelope.get("salt"), "salt", 128)
    if len(salt) != 16:
        raise CryptoError("Invalid salt length.")
    key = _derive_key(passphrase, salt, algorithm)
    try:
        if algorithm == "Fernet":
            token = envelope.get("ciphertext")
            if not isinstance(token, str) or len(token) > MAX_PACKET_LENGTH:
                raise CryptoError("Invalid ciphertext.")
            plaintext = Fernet(base64.urlsafe_b64encode(key)).decrypt(token.encode("ascii"))
        else:
            nonce = _decode(envelope.get("nonce"), "nonce", 128)
            if len(nonce) != 12:
                raise CryptoError("Invalid nonce length.")
            ciphertext = _decode(envelope.get("ciphertext"), "ciphertext")
            cipher = AESGCM(key) if algorithm.startswith("AES-") else ChaCha20Poly1305(key)
            plaintext = cipher.decrypt(nonce, ciphertext, _aad(algorithm, context))
    except (InvalidToken, InvalidTag, UnicodeError, ValueError) as exc:
        raise CryptoError("Unable to decrypt. Check the passphrase, room, and ciphertext.") from exc
    try:
        obj = json.loads(plaintext.decode("utf-8"))
        if not isinstance(obj, dict) or obj.get("context") != context or not isinstance(obj.get("data"), dict):
            raise CryptoError("Packet does not belong to this context.")
        return obj["data"]
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise CryptoError("Decrypted contents are not a valid message.") from exc


def generate_rsa_keys(directory: str, password: str, bits: int = 3072) -> tuple[str, str]:
    """Create a password-protected private PEM (0600) and shareable public PEM."""
    if not isinstance(password, str) or len(password) < 12:
        raise CryptoError("RSA private-key password must be at least 12 characters.")
    if bits not in (3072, 4096):
        raise CryptoError("Supported RSA sizes are 3072 and 4096 bits.")
    folder = Path(directory)
    if not folder.is_dir():
        raise CryptoError("Select an existing folder for your keys.")
    private_path = folder / "noxcipher_private.pem"
    public_path = folder / "noxcipher_public.pem"
    if private_path.exists() or public_path.exists():
        raise CryptoError("Key files already exist in this folder; choose an empty folder.")
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.BestAvailableEncryption(password.encode("utf-8")))
    public_data = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    # Create exclusively, avoid overwriting existing keys, and restrict private-key permissions.
    fd = os.open(private_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(private_data)
        with public_path.open("xb") as stream:
            stream.write(public_data)
    except Exception:
        private_path.unlink(missing_ok=True)
        raise
    return str(private_path), str(public_path)


def rsa_encrypt_text(message: str, public_pem: bytes) -> dict[str, Any]:
    if len(message) > MAX_TEXT_LENGTH:
        raise CryptoError("Text exceeds 5000 characters.")
    try:
        public_key = serialization.load_pem_public_key(public_pem)
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
            raise CryptoError("A valid RSA public key (2048 bits or stronger) is required.")
        session_key = os.urandom(32)
        nonce = os.urandom(12)
        wrapped = public_key.encrypt(session_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                        algorithm=hashes.SHA256(), label=None))
        ciphertext = AESGCM(session_key).encrypt(nonce, message.encode("utf-8"), b"noxcipher-rsa-hybrid-v1")
        return {"version": VERSION, "algorithm": HYBRID_ALGORITHM, "wrapped_key": _encode(wrapped),
                "nonce": _encode(nonce), "ciphertext": _encode(ciphertext)}
    except CryptoError:
        raise
    except (TypeError, ValueError) as exc:
        raise CryptoError("Cannot read the selected RSA public key.") from exc


def rsa_decrypt_text(envelope: dict[str, Any], private_pem: bytes, password: str) -> str:
    if not isinstance(envelope, dict) or envelope.get("version") != VERSION or envelope.get("algorithm") != HYBRID_ALGORITHM:
        raise CryptoError("This is not a supported RSA hybrid packet.")
    try:
        private_key = serialization.load_pem_private_key(private_pem, password=password.encode("utf-8") if password else None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise CryptoError("The selected key is not an RSA private key.")
        wrapped_key = _decode(envelope.get("wrapped_key"), "wrapped key", 2048)
        nonce = _decode(envelope.get("nonce"), "nonce", 128)
        ciphertext = _decode(envelope.get("ciphertext"), "ciphertext")
        if len(nonce) != 12:
            raise CryptoError("Invalid nonce length.")
        key = private_key.decrypt(wrapped_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                    algorithm=hashes.SHA256(), label=None))
        if len(key) != 32:
            raise CryptoError("Invalid wrapped session key.")
        return AESGCM(key).decrypt(nonce, ciphertext, b"noxcipher-rsa-hybrid-v1").decode("utf-8")
    except CryptoError:
        raise
    except (ValueError, TypeError, InvalidTag, UnicodeError) as exc:
        raise CryptoError("RSA decryption failed. Check the private key, password, and packet.") from exc


def classical_cipher(text: str, algorithm: str, key: str = "", decrypt: bool = False) -> str:
    """Educational substitution ciphers: NOT secure and NOT used in private chat."""
    if algorithm not in CLASSICAL_ALGORITHMS:
        raise CryptoError("Choose a supported classical cipher.")
    if algorithm == "ROT13":
        offset = 13
    elif algorithm == "Caesar":
        try:
            offset = int(key) % 26
        except ValueError as exc:
            raise CryptoError("Caesar cipher requires a numeric shift (e.g., 3).") from exc
    elif algorithm == "Vigenere":
        if not re.fullmatch("[A-Za-z]+", key or ""):
            raise CryptoError("Vigenere key must contain English letters only.")
        offsets = [ord(letter.upper()) - 65 for letter in key]
    output = []
    position = 0
    for letter in text:
        if "A" <= letter <= "Z" or "a" <= letter <= "z":
            base = 65 if letter.isupper() else 97
            num = ord(letter) - base
            if algorithm == "Atbash":
                new_num = 25 - num
            elif algorithm == "Vigenere":
                amount = offsets[position % len(offsets)]
                new_num = (num - amount if decrypt else num + amount) % 26
                position += 1
            else:
                new_num = (num - offset if decrypt else num + offset) % 26
            output.append(chr(base + new_num))
        else:
            output.append(letter)
    return "".join(output)


def hash_text(text: str, algorithm: str) -> str:
    data = text.encode("utf-8")
    if algorithm == "SHA-256":
        return hashlib.sha256(data).hexdigest()
    if algorithm == "SHA3-256":
        return hashlib.sha3_256(data).hexdigest()
    if algorithm == "SHA-512":
        return hashlib.sha512(data).hexdigest()
    if algorithm == "BLAKE2b-256":
        return hashlib.blake2b(data, digest_size=32).hexdigest()
    raise CryptoError("Unsupported hash algorithm.")
