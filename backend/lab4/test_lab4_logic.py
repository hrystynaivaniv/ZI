import unittest
from backend.lab4.lab4_logic import generate_rsa_keys, rsa_encrypt_file, rsa_decrypt_file

class TestRSAAlgorithm(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv_pem, cls.pub_pem = generate_rsa_keys(2048)
        cls.priv_pem_alt, cls.pub_pem_alt = generate_rsa_keys(2048)

    def test_key_generation_format(self):
        priv, pub = generate_rsa_keys(2048)
        self.assertIn(b"BEGIN PRIVATE KEY", priv)
        self.assertIn(b"BEGIN PUBLIC KEY", pub)
        self.assertTrue(len(priv) > 0)
        self.assertTrue(len(pub) > 0)

    def test_encrypt_decrypt_short_message(self):
        data = b"Hello, RSA with OAEP padding!"
        enc = rsa_encrypt_file(data, self.pub_pem)
        dec = rsa_decrypt_file(enc, self.priv_pem)
        self.assertEqual(data, dec)

    def test_encrypt_decrypt_large_message(self):
        data = b"A" * 600
        enc = rsa_encrypt_file(data, self.pub_pem)
        self.assertEqual(len(enc), 4 * 256)
        dec = rsa_decrypt_file(enc, self.priv_pem)
        self.assertEqual(data, dec)

    def test_encrypt_decrypt_empty_message(self):
        data = b""
        enc = rsa_encrypt_file(data, self.pub_pem)
        dec = rsa_decrypt_file(enc, self.priv_pem)
        self.assertEqual(data, dec)

    def test_decryption_failure_on_corrupted_data(self):
        data = b"Top secret information"
        enc = bytearray(rsa_encrypt_file(data, self.pub_pem))
        enc[5] ^= 0xFF
        with self.assertRaises(Exception):
            rsa_decrypt_file(bytes(enc), self.priv_pem)

    def test_exact_chunk_size_message(self):
        data = b"B" * 190
        enc = rsa_encrypt_file(data, self.pub_pem)
        self.assertEqual(len(enc), 256)
        dec = rsa_decrypt_file(enc, self.priv_pem)
        self.assertEqual(data, dec)

    def test_slightly_larger_than_chunk_size_message(self):
        data = b"C" * 191
        enc = rsa_encrypt_file(data, self.pub_pem)
        self.assertEqual(len(enc), 512)
        dec = rsa_decrypt_file(enc, self.priv_pem)
        self.assertEqual(data, dec)

    def test_wrong_key_pair_decryption(self):
        data = b"Strictly confidential"
        enc = rsa_encrypt_file(data, self.pub_pem)
        with self.assertRaises(Exception):
            rsa_decrypt_file(enc, self.priv_pem_alt)

    def test_invalid_public_key(self):
        data = b"Test"
        invalid_pub = b"-----BEGIN PUBLIC KEY-----\nINVALIDDATA\n-----END PUBLIC KEY-----"
        with self.assertRaises(Exception):
            rsa_encrypt_file(data, invalid_pub)

    def test_invalid_private_key(self):
        data = b"Test"
        enc = rsa_encrypt_file(data, self.pub_pem)
        invalid_priv = b"-----BEGIN PRIVATE KEY-----\nINVALIDDATA\n-----END PRIVATE KEY-----"
        with self.assertRaises(Exception):
            rsa_decrypt_file(enc, invalid_priv)

    def test_truncated_ciphertext(self):
        data = b"Truncated test"
        enc = rsa_encrypt_file(data, self.pub_pem)
        truncated_enc = enc[:-10]
        with self.assertRaises(Exception):
            rsa_decrypt_file(truncated_enc, self.priv_pem)

    def test_different_key_size_1024(self):
        priv_1024, pub_1024 = generate_rsa_keys(1024)
        data = b"Test 1024"
        enc = rsa_encrypt_file(data, pub_1024)
        dec = rsa_decrypt_file(enc, priv_1024)
        self.assertEqual(data, dec)

    def test_different_key_size_3072(self):
        priv_3072, pub_3072 = generate_rsa_keys(3072)
        data = b"Test 3072"
        enc = rsa_encrypt_file(data, pub_3072)
        dec = rsa_decrypt_file(enc, priv_3072)
        self.assertEqual(data, dec)

    def test_binary_data_encryption(self):
        data = bytes([i % 256 for i in range(1000)])
        enc = rsa_encrypt_file(data, self.pub_pem)
        dec = rsa_decrypt_file(enc, self.priv_pem)
        self.assertEqual(data, dec)

if __name__ == '__main__':
    unittest.main()