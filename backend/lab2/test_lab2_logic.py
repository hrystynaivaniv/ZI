import unittest
from backend.lab2.lab2_logic import md5_string, md5_bytes, _left_rotate

class TestMD5Algorithm(unittest.TestCase):
    def test_empty_string(self):
        self.assertEqual(md5_string("").upper(), "D41D8CD98F00B204E9800998ECF8427E")

    def test_single_char(self):
        self.assertEqual(md5_string("a").upper(), "0CC175B9C0F1B6A831C399E269772661")

    def test_abc(self):
        self.assertEqual(md5_string("abc").upper(), "900150983CD24FB0D6963F7D28E17F72")

    def test_message_digest(self):
        self.assertEqual(md5_string("message digest").upper(), "F96B697D7CB7938D525A2F31AAF161D0")

    def test_alphabet(self):
        self.assertEqual(md5_string("abcdefghijklmnopqrstuvwxyz").upper(), "C3FCD3D76192E4007DFB496CCA67E13B")

    def test_alphanumeric(self):
        self.assertEqual(md5_string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").upper(), "D174AB98D277D9F5A5611C2C9F419D9F")

    def test_long_numbers(self):
        self.assertEqual(md5_string("12345678901234567890123456789012345678901234567890123456789012345678901234567890").upper(), "57EDF4A22BE3C955AC49DA2E2107B67A")

    def test_md5_bytes_direct(self):
        self.assertEqual(md5_bytes(b"abc").upper(), "900150983CD24FB0D6963F7D28E17F72")

    def test_left_rotate_basic(self):
        self.assertEqual(_left_rotate(1, 1), 2)
        self.assertEqual(_left_rotate(1, 31), 0x80000000)

    def test_left_rotate_overflow(self):
        self.assertEqual(_left_rotate(0x80000000, 1), 1)
        self.assertEqual(_left_rotate(0xFFFFFFFF, 10), 0xFFFFFFFF)

    def test_non_existent_file(self):
        with self.assertRaises(FileNotFoundError):
            with open("non_existent_file_123.txt", "rb") as f:
                md5_bytes(f.read())