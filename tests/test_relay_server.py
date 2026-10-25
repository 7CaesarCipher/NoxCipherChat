from fastapi.testclient import TestClient
from relay_server import app
from crypto_engine import encrypt_payload, decrypt_payload


def test_message_relay_two_clients():
    passphrase = "correct horse battery staple"
    with TestClient(app) as client:
        with client.websocket_connect("/ws/team_1") as alice:
            assert alice.receive_json()["type"] == "status"
            with client.websocket_connect("/ws/team_1") as bob:
                assert bob.receive_json()["type"] == "status"
                ciphertext = encrypt_payload({"kind": "chat", "message": "Hi Bob"}, passphrase,
                                             "AES-256-GCM", "room:team_1")
                alice.send_json({"type": "message", "data": ciphertext})
                packet_a = alice.receive_json()
                packet_b = bob.receive_json()
                assert packet_a["type"] == packet_b["type"] == "message"
                assert packet_a["data"] == packet_b["data"] == ciphertext
                assert decrypt_payload(packet_b["data"], passphrase, "room:team_1")["message"] == "Hi Bob"


def test_server_health():
    with TestClient(app) as client:
        data = client.get("/health").json()
        assert data["status"] == "ok"
        assert data["message_storage"] == "none"


def test_relay_rejects_unexpected_plaintext_fields():
    with TestClient(app) as client:
        with client.websocket_connect("/ws/test-room") as alice:
            alice.receive_json()
            packet = encrypt_payload({"text": "safe"}, "correct horse battery staple", "AES-256-GCM", "room:test-room")
            packet["plaintext"] = "should never be forwarded"
            alice.send_json({"type": "message", "data": packet})
            result = alice.receive_json()
            assert result["type"] == "error"
