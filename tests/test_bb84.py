import random
import unittest

from backend import bb84


class BB84Tests(unittest.TestCase):
    def setUp(self):
        random.seed(7)

    def test_normal_sifting(self):
        alice, bob = bb84.sift_key([1, 0, 1], [1, 1, 1], ["+", "x", "+"], ["+", "+", "+"])
        self.assertEqual(alice, [1, 1])
        self.assertEqual(bob, [1, 1])

    def test_error_rate_below_threshold(self):
        result = bb84.establish_key()
        self.assertLessEqual(result.error_rate, 0.15)
        self.assertTrue(result.accepted)
        self.assertEqual(len(result.key), 32)
        self.assertGreater(result.generated_bits, 0)
        self.assertEqual(result.matching_bases, len(result.sifted_bits))
        self.assertTrue(result.alice_basis_preview)
        self.assertTrue(result.bob_basis_preview)
        self.assertTrue(result.alice_bit_preview)
        self.assertTrue(result.bob_bit_preview)
        self.assertTrue(result.keep_preview)
        self.assertEqual(len(result.alice_basis_preview), len(result.keep_preview))
        self.assertTrue(result.sifted_preview)

    def test_error_rate_above_threshold(self):
        self.assertGreater(bb84.calculate_error_rate([1, 1, 1, 1], [0, 0, 1, 1]), 0.15)

    def test_eavesdropper_bit_flip_scenario(self):
        result = bb84.establish_key(eavesdrop=True, bit_flip_rate=1.0)
        self.assertGreater(result.error_rate, 0.15)
        self.assertFalse(result.accepted)


if __name__ == "__main__":
    unittest.main()
