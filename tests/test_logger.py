import unittest

from backend import logger


class LoggerTests(unittest.TestCase):
    def setUp(self):
        logger.clear_events()

    def test_emit_and_clear_events(self):
        logger.emit_event("test", "message", "success", value=1)
        events = logger.get_events()
        self.assertEqual(events[0]["source"], "test")
        self.assertEqual(events[0]["value"], 1)
        logger.clear_events()
        self.assertEqual(logger.get_events(), [])


if __name__ == "__main__":
    unittest.main()

