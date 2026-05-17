import unittest

from backend import crypto_utils


class CryptoUtilsTests(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        payload = crypto_utils.encrypt_message("secret", b"shared-key")
        self.assertEqual(crypto_utils.decrypt_message(payload, b"shared-key"), "secret")

    def test_wrong_key_fails(self):
        payload = crypto_utils.encrypt_message("secret", b"shared-key")
        with self.assertRaises(Exception):
            crypto_utils.decrypt_message(payload, b"wrong-key")

    def test_empty_message(self):
        payload = crypto_utils.encrypt_message("", b"shared-key")
        self.assertEqual(crypto_utils.decrypt_message(payload, b"shared-key"), "")

    def test_hex_key_transport_roundtrip(self):
        key = b"x" * 32
        payload = crypto_utils.encrypt_message("secret", key)
        self.assertEqual(crypto_utils.decrypt_message(payload, key.hex()), "secret")


if __name__ == "__main__":
    unittest.main()

