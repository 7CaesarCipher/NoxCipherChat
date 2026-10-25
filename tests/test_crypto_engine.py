import base64
import json
import tempfile
import unittest
from pathlib import Path

from crypto_engine import (CLASSICAL_ALGORITHMS, SECURE_ALGORITHMS, CryptoError,
                           classical_cipher, decrypt_payload, encrypt_payload,
                           generate_rsa_keys, hash_text, rsa_decrypt_text,
                           rsa_encrypt_text)


PASS = "correct horse battery staple"


class CipherTests(unittest.TestCase):
    def test_symmetric_roundtrip(self):
        for algorithm in SECURE_ALGORITHMS:
            with self.subTest(algorithm=algorithm):
                payload = {"kind": "chat", "text": "Hello नमस्ते 🔐"}
                envelope = encrypt_payload(payload, PASS, algorithm, "room:test")
                self.assertNotIn("Hello", json.dumps(envelope))
                self.assertEqual(decrypt_payload(envelope, PASS, "room:test"), payload)

    def test_wrong_password_and_context(self):
        for algorithm in SECURE_ALGORITHMS:
            envelope = encrypt_payload({"text": "secret"}, PASS, algorithm, "room:test")
            with self.subTest(algorithm=algorithm), self.assertRaises(CryptoError):
                decrypt_payload(envelope, "something other password", "room:test")
            with self.assertRaises(CryptoError):
                decrypt_payload(envelope, PASS, "room:different")

    def test_ciphertext_tamper_detected(self):
        for algorithm in SECURE_ALGORITHMS:
            packet = encrypt_payload({"text": "no editing"}, PASS, algorithm, "room:test")
            packet["ciphertext"] = "AAAA" + packet["ciphertext"][4:]
            with self.subTest(algorithm=algorithm), self.assertRaises(CryptoError):
                decrypt_payload(packet, PASS, "room:test")

    def test_unique_packets(self):
        a = encrypt_payload({"message": "identical"}, PASS, "AES-256-GCM", "playground")
        b = encrypt_payload({"message": "identical"}, PASS, "AES-256-GCM", "playground")
        self.assertNotEqual(a["salt"], b["salt"])
        self.assertNotEqual(a["ciphertext"], b["ciphertext"])

    def test_rsa_hybrid(self):
        with tempfile.TemporaryDirectory() as directory:
            private_path, public_path = generate_rsa_keys(directory, PASS)
            self.assertTrue(Path(private_path).exists())
            ciphertext = rsa_encrypt_text("a long message नमस्ते 🔐", Path(public_path).read_bytes())
            self.assertEqual("a long message नमस्ते 🔐", rsa_decrypt_text(ciphertext, Path(private_path).read_bytes(), PASS))
            with self.assertRaises(CryptoError):
                rsa_decrypt_text(ciphertext, Path(private_path).read_bytes(), "a very wrong password")

    def test_classical_roundtrip(self):
        for algo in CLASSICAL_ALGORITHMS:
            key = "ABC" if algo == "Vigenere" else "5"
            text = "Secret Message! 123"
            encoded = classical_cipher(text, algo, key)
            decoded = classical_cipher(encoded, algo, key, decrypt=True)
            self.assertEqual(text, decoded)

    def test_hashes(self):
        self.assertEqual(len(hash_text("abc", "SHA-256")), 64)
        self.assertEqual(len(hash_text("abc", "SHA3-256")), 64)
        self.assertEqual(len(hash_text("abc", "SHA-512")), 128)
        self.assertEqual(len(hash_text("abc", "BLAKE2b-256")), 64)


if __name__ == "__main__":
    unittest.main()
