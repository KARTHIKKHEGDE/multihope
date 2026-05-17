import unittest

from backend import attack_detector, logger, receiver, router, sender


def local_receiver_transport(next_hop, packet):
    if next_hop == "receiver":
        return receiver.receive_packet(packet)
    return None


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        attack_detector.reset_detector()
        logger.clear_events()
        router.reset_routes()

    def test_message_through_all_hops_reaches_receiver(self):
        plaintext = sender.send_message("integration", transport=local_receiver_transport)
        self.assertEqual(plaintext, "integration")
        events = logger.get_events()
        sources = [event["source"] for event in events if event["status"] == "success"]
        self.assertEqual(sources, ["sender", "node1", "node2", "node3", "receiver"])
        phases = {event.get("phase") for event in events}
        self.assertIn("bb84", phases)
        self.assertIn("aes-decrypt", phases)
        self.assertIn("aes-encrypt", phases)

    def test_mitm_attack_blocks_route(self):
        attack_detector.set_attack_mode("mitm")
        self.assertIsNone(sender.send_message("blocked", transport=local_receiver_transport))
        attacks = [event for event in logger.get_events() if event["status"] == "attack"]
        self.assertEqual(attacks[-1]["phase"], "attack-detected")
        self.assertEqual(attacks[-1]["blockedNode"], "node1")
        self.assertEqual(router.get_node_statuses()["node1"]["status"], "blocked")

    def test_replay_attack_blocks_route(self):
        attack_detector.set_attack_mode("replay")
        self.assertIsNone(sender.send_message("replayed", transport=local_receiver_transport))
        attacks = [event for event in logger.get_events() if event["status"] == "attack"]
        self.assertIn("replay", attacks[-1]["message"])
        self.assertEqual(router.get_node_statuses()["node1"]["status"], "blocked")

    def test_eavesdrop_error_rate_blocks_route(self):
        attack_detector.set_attack_mode("eavesdrop")
        self.assertIsNone(sender.send_message("watched", transport=local_receiver_transport))
        attacks = [event for event in logger.get_events() if event["status"] == "attack"]
        self.assertIn("BB84 error rate", attacks[-1]["message"])
        self.assertEqual(router.get_node_statuses()["node1"]["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
