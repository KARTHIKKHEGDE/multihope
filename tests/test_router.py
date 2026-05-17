import unittest

from backend import router


class RouterTests(unittest.TestCase):
    def setUp(self):
        router.reset_routes()

    def test_next_hop_uses_active_route(self):
        self.assertEqual(router.get_next_hop("sender"), "node1")

    def test_block_node_reroutes_around_it(self):
        router.block_node("node2")
        self.assertEqual(router.get_next_hop("node1"), "node3")
        self.assertEqual(router.get_node_statuses()["node2"]["status"], "blocked")


if __name__ == "__main__":
    unittest.main()

