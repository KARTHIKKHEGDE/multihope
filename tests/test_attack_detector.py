import unittest

from backend import attack_detector


class AttackDetectorTests(unittest.TestCase):
    def setUp(self):
        attack_detector.reset_detector()

    def test_mitm_flag_triggers(self):
        result = attack_detector.inspect_packet("nonce-1", 0.0, mitm_flag=True)
        self.assertFalse(result.ok)
        self.assertEqual(result.status, "attack")

    def test_replay_nonce_detection(self):
        self.assertTrue(attack_detector.register_nonce("nonce-1").ok)
        result = attack_detector.register_nonce("nonce-1")
        self.assertFalse(result.ok)
        self.assertIn("replay", result.reason)

    def test_replay_nonce_expires_after_ttl(self):
        self.assertTrue(attack_detector.register_nonce("nonce-1", timestamp=0).ok)
        result = attack_detector.register_nonce("nonce-1", timestamp=61)
        self.assertTrue(result.ok)

    def test_clean_pass_through(self):
        result = attack_detector.inspect_packet("nonce-1", 0.0)
        self.assertTrue(result.ok)
        self.assertEqual(result.status, "ok")

    def test_error_rate_detection(self):
        self.assertTrue(attack_detector.is_error_rate_attack(0.2))
        self.assertFalse(attack_detector.is_error_rate_attack(0.15))


if __name__ == "__main__":
    unittest.main()
