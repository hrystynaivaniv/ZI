import unittest
import math
import os

from backend.lab1.lab1_logic import lcg_generate, find_gcd, test_cesaro, get_period, save_to_file


class TestLab1Logic(unittest.TestCase):

    def test_find_gcd(self):
        self.assertEqual(find_gcd(14, 28), 14)
        self.assertEqual(find_gcd(15, 28), 1)
        self.assertEqual(find_gcd(17, 34), 17)
        self.assertEqual(find_gcd(100, 10), 10)

    def test_lcg_generate_length(self):
        numbers = lcg_generate(count=15)
        self.assertEqual(len(numbers), 15)

    def test_lcg_generate_logic(self):
        numbers = lcg_generate(count=3, m=10, a=3, c=1, x0=2)
        self.assertEqual(numbers, [7, 2, 7])

    def test_get_period(self):
        period = get_period(m=10, a=3, c=1, x0=2)
        self.assertEqual(period, 2)

    def test_cesaro_empty_or_short(self):
        self.assertEqual(test_cesaro([]), 0)
        self.assertEqual(test_cesaro([123]), 0)

    def test_cesaro_no_coprimes(self):
        self.assertEqual(test_cesaro([2, 4, 6, 8]), 0)

    def test_cesaro_with_coprimes(self):
        expected_pi = math.sqrt(6)
        self.assertEqual(test_cesaro([3, 4, 5, 9]), expected_pi)

    def test_save_to_file(self):
        test_filename = "test_temp_output.txt"
        test_data = [10, 20, 30, 40]

        save_to_file(test_filename, test_data)

        self.assertTrue(os.path.exists(test_filename))

        with open(test_filename, 'r') as f:
            lines = f.readlines()

        self.assertEqual(len(lines), 4)
        self.assertEqual(lines[0].strip(), "10")
        self.assertEqual(lines[-1].strip(), "40")

        if os.path.exists(test_filename):
            os.remove(test_filename)

