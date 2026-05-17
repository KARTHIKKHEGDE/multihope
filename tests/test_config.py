import unittest

from backend import config


class ConfigTests(unittest.TestCase):
    def test_required_config_values_exist(self):
        self.assertIn("node1", config.NODE_PORTS)
        self.assertIn("receiver", config.NODE_PORTS)
        self.assertIsInstance(config.API_PORT, int)
        self.assertGreater(config.SOCKET_TIMEOUT_SECONDS, 0)
        self.assertLess(config.ERROR_THRESHOLD, 1)
        self.assertEqual(config.EAVESDROP_BIT_FLIP_RATE, 1.0)
        self.assertIn("replay", config.VALID_ATTACK_MODES)


if __name__ == "__main__":
    unittest.main()
