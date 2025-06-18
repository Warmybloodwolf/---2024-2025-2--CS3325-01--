#!/usr/bin/env python3
"""
Textbook RSA implementation for assignment.

Features:
- Key pair generation (1024‑bit modulus)
- Encryption & decryption
- Outputs files required by requirement.md

Usage:
    python textbook_rsa_assignment.py generate   # generate keys & parameter files
    python textbook_rsa_assignment.py encrypt <input_plaintext_file>
    python textbook_rsa_assignment.py decrypt <input_cipher_hex_file>
"""

import os
import sys
import random
import math
from typing import Tuple

RAND = random.SystemRandom()


def is_probable_prime(n: int, k: int = 40) -> bool:
    """Miller–Rabin primality test."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    # write n-1 as 2^s * d
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    # witness loop
    for _ in range(k):
        a = RAND.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate a random prime of specified bit length."""
    while True:
        # ensure highest bit set
        candidate = RAND.getrandbits(bits) | (1 << bits - 1) | 1
        if is_probable_prime(candidate):
            return candidate


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a: int, m: int) -> int:
    """Modular inverse of a modulo m."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Inverse does not exist")
    return x % m


def keygen(bits: int = 1024) -> Tuple[int, int, int, int, int]:
    """Generate RSA parameters (p, q, n, e, d)."""
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while q == p:
        q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if math.gcd(e, phi) != 1:
        # rare, regenerate
        return keygen(bits)
    d = modinv(e, phi)
    return p, q, n, e, d


def int_from_bytes(data: bytes) -> int:
    return int.from_bytes(data, byteorder="big")


def int_to_bytes(n: int, length: int = None) -> bytes:
    if length is None:
        length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder="big")


def encrypt(m: int, e: int, n: int) -> int:
    if m >= n:
        raise ValueError("Message representative out of range")
    return pow(m, e, n)


def decrypt(c: int, d: int, n: int) -> int:
    return pow(c, d, n)

# ---------- File helpers ----------

def write_decimal(path: str, value: int):
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(value))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    command = sys.argv[1]
    if command == "generate":
        p, q, n, e, d = keygen()
        write_decimal("RSA_p.txt", p)
        write_decimal("RSA_q.txt", q)
        write_decimal("RSA_Moduler.txt", n)
        write_decimal("RSA_Secret_Key.txt", d)
        write_decimal("RSA_Public_Key.txt", e)
        print("[+] Key pair generated and files written.")
    elif command == "encrypt":
        if len(sys.argv) != 3:
            print("Usage: encrypt <Raw_Message.txt>")
            sys.exit(1)
        path = sys.argv[2]
        with open(path, "rb") as f:
            plaintext = f.read()
        m = int_from_bytes(plaintext)
        n = int(open("RSA_Moduler.txt").read().strip())
        e = int(open("RSA_Public_Key.txt").read().strip())
        c = encrypt(m, e, n)
        with open("Encrypted_Message.txt", "w") as f:
            f.write(hex(c)[2:])  # store hex without '0x'
        print("[+] Message encrypted to Encrypted_Message.txt")
    elif command == "decrypt":
        if len(sys.argv) != 3:
            print("Usage: decrypt <Encrypted_Message.txt>")
            sys.exit(1)
        path = sys.argv[2]
        with open(path, "r") as f:
            c_hex = f.read().strip()
        c = int(c_hex, 16)
        n = int(open("RSA_Moduler.txt").read().strip())
        d = int(open("RSA_Secret_Key.txt").read().strip())
        m = decrypt(c, d, n)
        plaintext = int_to_bytes(m)
        # verify against modulus length
        with open("Decrypted_Message.txt", "wb") as f:
            f.write(plaintext.lstrip(b"\x00"))
        print("[+] Ciphertext decrypted to Decrypted_Message.txt")
    else:
        print("Unknown command:", command)
        sys.exit(1)


if __name__ == "__main__":
    main()
