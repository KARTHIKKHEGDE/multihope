import unittest
import json
from unittest.mock import patch

from backend import attack_detector, logger, router, sender, node


class FakeConnection:
    def __init__(self, response):
        self.response = response
        self.sent = b""

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        return False

    def sendall(self, data):
        self.sent += data

    def recv(self, _buffer_size):
        return self.response


class NodeTests(unittest.TestCase):
    def setUp(self):
        attack_detector.reset_detector()
        logger.clear_events()
        router.reset_routes()

    def test_process_packet_forwards_clean_packet(self):
        packet = sender.build_initial_packet("hello")
        processed = node.process_packet("node1", packet)
        self.assertIsNotNone(processed)
        self.assertIn("node1", processed["route"])

    def test_process_packet_blocks_mitm(self):
        packet = sender.build_initial_packet("hello")
        packet["mitm"] = True
        self.assertIsNone(node.process_packet("node1", packet))
        self.assertEqual(router.get_node_statuses()["node1"]["status"], "blocked")

    def test_send_packet_to_receiver_uses_tcp_response(self):
        response = json.dumps({
            "ok": True,
            "plaintext": "hello",
            "receiverEvents": [
                {
                    "time": "ignored",
                    "source": "receiver",
                    "message": "Received plaintext: hello",
                    "status": "success",
                    "plaintext": "hello",
                }
            ],
        }).encode("utf-8")
        fake_connection = FakeConnection(response)
        with patch("backend.node.socket.create_connection", return_value=fake_connection):
            self.assertEqual(node.send_packet_to_receiver({"payload": {}, "key": "key"}), "hello")
        self.assertTrue(fake_connection.sent)
        self.assertTrue(any(event["source"] == "receiver" for event in logger.get_events()))


if __name__ == "__main__":
    unittest.main()
