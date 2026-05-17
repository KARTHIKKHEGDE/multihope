import unittest

from backend import attack_detector, logger, receiver, router, sender


def local_receiver_transport(next_hop, packet):
    if next_hop == "receiver":
        return receiver.receive_packet(packet)
    return None


class SenderTests(unittest.TestCase):
    def setUp(self):
        attack_detector.reset_detector()
        logger.clear_events()
        router.reset_routes()

    def test_build_initial_packet(self):
        packet = sender.build_initial_packet("hello")
        self.assertIn("payload", packet)
        self.assertIn("nonce", packet)
        self.assertEqual(packet["route"], ["sender"])

    def test_send_message_returns_receiver_plaintext(self):
        self.assertEqual(sender.send_message("hello", transport=local_receiver_transport), "hello")


if __name__ == "__main__":
    unittest.main()
