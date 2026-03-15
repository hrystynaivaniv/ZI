import os
from backend.lab1.lab1_logic import lcg_generate
from backend.lab2.lab2_logic import md5_string


def _rotl(x, y, w):
    mod = (1 << w) - 1
    y = y % w
    return ((x << y) | (x >> (w - y))) & mod


def _rotr(x, y, w):
    mod = (1 << w) - 1
    y = y % w
    return ((x >> y) | (x << (w - y))) & mod


def _derive_key(pwd, b):
    h_hex = md5_string(pwd)
    h = bytes.fromhex(h_hex)
    if b == 8:
        return h[:8]
    elif b == 32:
        hh = bytes.fromhex(md5_string(h_hex))
        return hh + h
    return h[:b]


def _key_expansion(pwd, w, r, b):
    key = _derive_key(pwd, b)
    u = w // 8
    mod = (1 << w) - 1

    if w == 16:
        P, Q = 0xB7E1, 0x9E37
    elif w == 32:
        P, Q = 0xB7E15163, 0x9E3779B9
    else:
        P, Q = 0xB7E151628AED2A6B, 0x9E3779B97F4A7C15

    c = max(1, (b + u - 1) // u)
    L = [0] * c
    for i in range(b):
        L[i // u] = (L[i // u] + (key[i] << (8 * (i % u)))) & mod

    S = [0] * (2 * r + 2)
    S[0] = P
    for i in range(1, len(S)):
        S[i] = (S[i - 1] + Q) & mod

    i = j = A = B = 0
    t = max(c, 2 * r + 2)
    for _ in range(3 * t):
        A = S[i] = _rotl((S[i] + A + B) & mod, 3, w)
        B = L[j] = _rotl((L[j] + A + B) & mod, A + B, w)
        i = (i + 1) % len(S)
        j = (j + 1) % c
    return S


def _rc5_encrypt_block(block_bytes, S, w, r):
    u = w // 8
    mod = (1 << w) - 1
    A = int.from_bytes(block_bytes[:u], 'little')
    B = int.from_bytes(block_bytes[u:], 'little')

    A = (A + S[0]) & mod
    B = (B + S[1]) & mod
    for i in range(1, r + 1):
        A = (_rotl(A ^ B, B, w) + S[2 * i]) & mod
        B = (_rotl(B ^ A, A, w) + S[2 * i + 1]) & mod

    return A.to_bytes(u, 'little') + B.to_bytes(u, 'little')


def _rc5_decrypt_block(block_bytes, S, w, r):
    u = w // 8
    mod = (1 << w) - 1
    A = int.from_bytes(block_bytes[:u], 'little')
    B = int.from_bytes(block_bytes[u:], 'little')

    for i in range(r, 0, -1):
        B = _rotr((B - S[2 * i + 1]) & mod, A, w) ^ A
        A = _rotr((A - S[2 * i]) & mod, B, w) ^ B
    B = (B - S[1]) & mod
    A = (A - S[0]) & mod

    return A.to_bytes(u, 'little') + B.to_bytes(u, 'little')


def encrypt_file_data(data, w, r, b, pwd):
    S = _key_expansion(pwd, w, r, b)
    u = w // 8
    block_size = 2 * u

    iv_ints = lcg_generate(block_size)
    iv = bytes(x % 256 for x in iv_ints)

    pad_len = block_size - (len(data) % block_size)
    data += bytes([pad_len] * pad_len)

    enc_iv = _rc5_encrypt_block(iv, S, w, r)
    out = bytearray(enc_iv)

    prev_block = iv
    for i in range(0, len(data), block_size):
        chunk = data[i:i + block_size]
        xor_block = bytes(x ^ y for x, y in zip(chunk, prev_block))
        enc_block = _rc5_encrypt_block(xor_block, S, w, r)
        out.extend(enc_block)
        prev_block = enc_block

    return bytes(out)


def decrypt_file_data(data, w, r, b, pwd):
    S = _key_expansion(pwd, w, r, b)
    u = w // 8
    block_size = 2 * u

    enc_iv = data[:block_size]
    iv = _rc5_decrypt_block(enc_iv, S, w, r)

    out = bytearray()
    prev_block = iv
    for i in range(block_size, len(data), block_size):
        enc_block = data[i:i + block_size]
        dec_block = _rc5_decrypt_block(enc_block, S, w, r)
        out.extend(bytes(x ^ y for x, y in zip(dec_block, prev_block)))
        prev_block = enc_block

    pad_len = out[-1]
    return bytes(out[:-pad_len])