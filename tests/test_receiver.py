import unittest
import json

from backend import crypto_utils, logger, receiver


class FakeSocket:
    def __init__(self, payload):
        self.payload = payload
        self.sent = b""

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        return False

    def recv(self, _buffer_size):
        return self.payload

    def sendall(self, data):
        self.sent += data


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        logger.clear_events()

    def test_receive_packet_decrypts_and_logs(self):
        packet = {"payload": crypto_utils.encrypt_message("done", b"key"), "key": b"key"}
        self.assertEqual(receiver.receive_packet(packet), "done")
        self.assertEqual(logger.get_events()[0]["source"], "receiver")

    def test_handle_client_returns_plaintext_response(self):
        packet = {"payload": crypto_utils.encrypt_message("done", b"key"), "key": "key"}
        client = FakeSocket(json.dumps(packet).encode("utf-8"))
        receiver.handle_client(client)
        response = json.loads(client.sent.decode("utf-8"))
        self.assertTrue(response["ok"])
        self.assertEqual(response["plaintext"], "done")
        self.assertEqual(response["receiverEvents"][-1]["source"], "receiver")
        self.assertEqual(response["receiverEvents"][-1]["status"], "success")


if __name__ == "__main__":
    unittest.main()
