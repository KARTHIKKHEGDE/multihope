import unittest
from unittest.mock import patch

from backend.app import app


class AppTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.post("/api/reset")

    def test_status_endpoint(self):
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        self.assertIn("node1", response.get_json())

    def test_send_endpoint(self):
        with patch("backend.app.sender.send_message", return_value="hello"):
            response = self.client.post("/api/send", json={"message": "hello"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["received"], "hello")

    def test_attack_endpoint(self):
        response = self.client.post("/api/attack", json={"mode": "mitm"})
        self.assertEqual(response.get_json()["mode"], "mitm")

    def test_attack_endpoint_rejects_unknown_mode(self):
        response = self.client.post("/api/attack", json={"mode": "unknown"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("unknown attack mode", response.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
