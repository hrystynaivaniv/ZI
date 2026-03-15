import math
import random

M = 2 ** 14 - 1
A = 6 ** 5
C = 5
X0 = 32


def lcg_generate(count, m=M, a=A, c=C, x0=X0):
    numbers = []
    current_x = x0
    for _ in range(count):
        current_x = (a * current_x + c) % m
        numbers.append(current_x)
    return numbers


def find_gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def test_cesaro(numbers):
    if len(numbers) < 2:
        return 0

    pairs_count = len(numbers) // 2
    count_gcd_1 = 0

    for i in range(0, pairs_count * 2, 2):
        if find_gcd(numbers[i], numbers[i + 1]) == 1:
            count_gcd_1 += 1

    if count_gcd_1 == 0:
        return 0

    probability = count_gcd_1 / pairs_count
    return math.sqrt(6 / probability)


def get_period(m=M, a=A, c=C, x0=X0):
    first_gen = (a * x0 + c) % m
    current_x = first_gen
    period = 1

    for _ in range(m + 1):
        current_x = (a * current_x + c) % m
        if current_x == first_gen:
            return period
        period += 1
    return period


def save_to_file(filename, numbers):
    with open(filename, 'w') as f:
        for n in numbers:
            f.write(f"{n}\n")