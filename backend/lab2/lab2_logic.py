import math
import os


def _left_rotate(x, c):
    return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF


def md5_bytes(msg_bytes):
    T = [int(2**32 * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)]
    A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4

    orig_len_bits = (len(msg_bytes) * 8) & 0xffffffffffffffff
    msg_bits = bytearray(msg_bytes)
    msg_bits.append(0x80)

    while len(msg_bits) % 64 != 56:
        msg_bits.append(0)

    msg_bits += orig_len_bits.to_bytes(8, byteorder='little')

    for i in range(0, len(msg_bits), 64):
        block = msg_bits[i:i + 64]
        X = [int.from_bytes(block[j:j + 4], byteorder='little') for j in range(0, 64, 4)]
        AA, BB, CC, DD = A, B, C, D

        for r in range(64):
            if 0 <= r <= 15:
                f = (B & C) | (~B & D)
                g = r
            elif 16 <= r <= 31:
                f = (D & B) | (~D & C)
                g = (5 * r + 1) % 16
            elif 32 <= r <= 47:
                f = B ^ C ^ D
                g = (3 * r + 5) % 16
            else:
                f = C ^ (B | ~D)
                g = (7 * r) % 16

            temp = (A + f + X[g] + T[r]) & 0xFFFFFFFF
            A, D, C = D, C, B
            B = (B + _left_rotate(temp, S[r])) & 0xFFFFFFFF

        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    return sum(x << (32 * i) for i, x in enumerate([A, B, C, D])).to_bytes(16, byteorder='little').hex()


def md5_string(text: str) -> str:
    return md5_bytes(text.encode('utf-8'))


def save_result_to_file(filepath, content):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)