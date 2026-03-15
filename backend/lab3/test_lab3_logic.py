import unittest
from backend.lab3.lab3_logic import (
    _rotl, _rotr, _rc5_encrypt_block, _rc5_decrypt_block,
    _key_expansion, encrypt_file_data, decrypt_file_data
)


class TestRC5Algorithm(unittest.TestCase):
    def test_rotations_w32(self):
        w = 32
        self.assertEqual(_rotl(1, 1, w), 2)
        self.assertEqual(_rotr(2, 1, w), 1)
        self.assertEqual(_rotl(0x80000000, 1, w), 1)
        self.assertEqual(_rotr(1, 1, w), 0x80000000)

    def test_rotations_w16(self):
        w = 16
        self.assertEqual(_rotl(1, 1, w), 2)
        self.assertEqual(_rotl(0x8000, 1, w), 1)

    def test_block_symmetry_w16(self):
        pwd = "test"
        w, r, b = 16, 12, 16
        S = _key_expansion(pwd, w, r, b)
        data = b'\x12\x34\x56\x78'
        enc = _rc5_encrypt_block(data, S, w, r)
        dec = _rc5_decrypt_block(enc, S, w, r)
        self.assertEqual(data, dec)

    def test_block_symmetry_w32(self):
        pwd = "password123"
        w, r, b = 32, 12, 16
        S = _key_expansion(pwd, w, r, b)
        data = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
        enc = _rc5_encrypt_block(data, S, w, r)
        dec = _rc5_decrypt_block(enc, S, w, r)
        self.assertEqual(data, dec)

    def test_block_symmetry_w64(self):
        pwd = "secure"
        w, r, b = 64, 12, 16
        S = _key_expansion(pwd, w, r, b)
        data = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
        enc = _rc5_encrypt_block(data, S, w, r)
        dec = _rc5_decrypt_block(enc, S, w, r)
        self.assertEqual(data, dec)

    def test_file_encryption_decryption_b8(self):
        pwd = "key"
        w, r, b = 32, 12, 8
        data = b"Hello, World!"
        enc = encrypt_file_data(data, w, r, b, pwd)
        dec = decrypt_file_data(enc, w, r, b, pwd)
        self.assertEqual(data, dec)

    def test_file_encryption_decryption_b32(self):
        pwd = "long_password"
        w, r, b = 32, 12, 32
        data = b"Testing RC5 CBC Pad with 32 byte key"
        enc = encrypt_file_data(data, w, r, b, pwd)
        dec = decrypt_file_data(enc, w, r, b, pwd)
        self.assertEqual(data, dec)

    def test_padding_length(self):
        pwd = "pad"
        w, r, b = 32, 12, 16
        data = b"12345"
        enc = encrypt_file_data(data, w, r, b, pwd)
        block_size = (w // 8) * 2
        self.assertEqual(len(enc) % block_size, 0)

    def test_empty_data(self):
        pwd = "empty"
        w, r, b = 32, 12, 16
        data = b""
        enc = encrypt_file_data(data, w, r, b, pwd)
        dec = decrypt_file_data(enc, w, r, b, pwd)
        self.assertEqual(data, dec)

    def test_large_data(self):
        pwd = "large"
        w, r, b = 32, 12, 16
        data = b"A" * 10000
        enc = encrypt_file_data(data, w, r, b, pwd)
        dec = decrypt_file_data(enc, w, r, b, pwd)
        self.assertEqual(data, dec)


if __name__ == '__main__':
    unittest.main()