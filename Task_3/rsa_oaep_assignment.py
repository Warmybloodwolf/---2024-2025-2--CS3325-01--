#!/usr/bin/env python3
"""RSA-OAEP (two-hash variant) for 1024-bit modulus.

Specification (matches Project - Task 3 slides)
------------------------------------------------
* n  = 1024 bits ⇒ k   = 128 bytes (RSA modulus size)
* k0 = 512  bits ⇒ 64  bytes (random string r & Y block size)
* k1 =   8  bits ⇒  1  byte  (fixed trailing zero byte)
* Hash functions **G** and **H** are both SHA-512:
    * G expands k0 bytes → (k − k0) bytes (take first 64 B)
    * H compresses (k − k0) bytes → k0 bytes (full 64 B)
* OAEP output is **X ∥ Y** (128 bytes) which is fed into textbook RSA.

CLI is drop-in compatible with `textbook_rsa_assignment.py`:

    python rsa_oaep_assignment.py generate
    python rsa_oaep_assignment.py encrypt Raw_Message.txt
    python rsa_oaep_assignment.py decrypt Encrypted_Message.txt

Files generated during *encrypt* conform to requirement.md:

| 文件 | 内容 |
|------|------|
| Random_Number.txt          | 随机串 *r* (hex, 64 B) |
| Message_After_Padding.txt  | OAEP 编码结果 *X∥Y* (hex, 128 B) |
| Encrypted_Message.txt      | RSA 密文 (hex) |
"""

from __future__ import annotations

import hashlib
import math
import os
import sys
from typing import Tuple

from textbook_rsa_assignment import (
    int_from_bytes,
    int_to_bytes,
    generate_prime,
    modinv,
    write_decimal,
)

# ---------- Protocol parameters ----------
MOD_BITS = 1024
MOD_BYTES = MOD_BITS // 8  # 128
K0_BYTES = 64              # 512 bits
K1_BYTES = 1               # 8 bits  — fixed 0x00 byte

HASH = hashlib.sha512
RAND = os.urandom

# ------------------------------------------------------------
# Helper: MGF based on SHA-512 (can truncate/expand as needed)
# ------------------------------------------------------------

def mgf_sha512(seed: bytes, out_len: int) -> bytes:
    """Generate *out_len* bytes using counter-based SHA-512 MGF."""
    blocks = []
    counter = 0
    while len(b"".join(blocks)) < out_len:
        cnt = counter.to_bytes(4, "big")
        blocks.append(HASH(seed + cnt).digest())
        counter += 1
    return b"".join(blocks)[:out_len]

# ------------------------------------------------------------
# OAEP encoding / decoding (two-hash variant)
# ------------------------------------------------------------

MAX_MSG_LEN = MOD_BYTES - K0_BYTES - K1_BYTES  # 63 bytes


def oaep_encode(msg: bytes) -> Tuple[bytes, bytes]:
    """Return (EM, r) where EM = X∥Y is 128 bytes."""
    if len(msg) > MAX_MSG_LEN:
        raise ValueError("message too long (max %d bytes)" % MAX_MSG_LEN)

    # Step 1 – pad message with k1 (=1) zero byte and zeros to length (k−k0)
    pad_len = (MOD_BYTES - K0_BYTES) - K1_BYTES - len(msg)
    m_padded = msg + b"\x00" * pad_len + b"\x00" * K1_BYTES  # m‖0…0 (k1 zeros)

    # Step 2 – generate random r (k0 bytes) and compute G(r)
    r = RAND(K0_BYTES)
    G_r = mgf_sha512(r, MOD_BYTES - K0_BYTES)  # 64 bytes

    # Step 3 – X = m_padded ⊕ G(r)
    X = bytes(a ^ b for a, b in zip(m_padded, G_r))

    # Step 4 – Y = r ⊕ H(X)
    H_X = HASH(X).digest()  # 64 bytes
    Y = bytes(a ^ b for a, b in zip(r, H_X))

    EM = X + Y  # 128 bytes
    return EM, r


def oaep_decode(em: bytes) -> bytes:
    if len(em) != MOD_BYTES:
        raise ValueError("encoded message length mismatch")
    X = em[: MOD_BYTES - K0_BYTES]
    Y = em[MOD_BYTES - K0_BYTES :]

    # Recover r
    r = bytes(a ^ b for a, b in zip(Y, HASH(X).digest()))

    # Recover m‖0…0
    m_padded = bytes(a ^ b for a, b in zip(X, mgf_sha512(r, MOD_BYTES - K0_BYTES)))

    # Strip trailing k1 zero byte and extra zeros
    if m_padded[-K1_BYTES:] != b"\x00" * K1_BYTES:
        raise ValueError("decoding error: k1 trailer mismatch")
    m_body = m_padded[: -K1_BYTES]
    # Remove additional zero padding (right-trim)
    m = m_body.rstrip(b"\x00")
    return m

# ------------------------------------------------------------
# Basic RSA (same as earlier)
# ------------------------------------------------------------

def keygen(bits: int = MOD_BITS):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while q == p:
        q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, phi)
    return p, q, n, e, d


def rsa_enc_int(m: int, e: int, n: int) -> int:
    if m >= n:
        raise ValueError("message representative out of range")
    return pow(m, e, n)


def rsa_dec_int(c: int, d: int, n: int) -> int:
    return pow(c, d, n)

# ------------------------------------------------------------
# File helpers
# ------------------------------------------------------------

def read_int(fname: str) -> int:
    return int(open(fname).read().strip())

# ------------------------------------------------------------
# CLI commands
# ------------------------------------------------------------

def cmd_generate():
    p, q, n, e, d = keygen()
    write_decimal("RSA_p.txt", p)
    write_decimal("RSA_q.txt", q)
    write_decimal("RSA_Moduler.txt", n)
    write_decimal("RSA_Public_Key.txt", e)
    write_decimal("RSA_Secret_Key.txt", d)
    print("[+] Generated 1024-bit RSA key pair.")


def cmd_encrypt(msg_path: str):
    n = read_int("RSA_Moduler.txt")
    e = read_int("RSA_Public_Key.txt")

    msg = open(msg_path, "rb").read()
    em, r = oaep_encode(msg)
    c_int = rsa_enc_int(int_from_bytes(em), e, n)

    open("Random_Number.txt", "w").write(r.hex())
    open("Message_After_Padding.txt", "w").write(em.hex())
    open("Encrypted_Message.txt", "w").write(hex(c_int)[2:])
    print("[+] Message encrypted with RSA-OAEP.")


def cmd_decrypt(ct_path: str):
    n = read_int("RSA_Moduler.txt")
    d = read_int("RSA_Secret_Key.txt")

    c_hex = open(ct_path).read().strip()
    c_int = int(c_hex, 16)
    em = int_to_bytes(rsa_dec_int(c_int, d, n), MOD_BYTES)
    msg = oaep_decode(em)
    open("Decrypted_Message.txt", "wb").write(msg)
    print("[+] Ciphertext decrypted successfully.")

# ------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    match sys.argv[1].lower():
        case "generate":
            cmd_generate()
        case "encrypt" if len(sys.argv) == 3:
            cmd_encrypt(sys.argv[2])
        case "decrypt" if len(sys.argv) == 3:
            cmd_decrypt(sys.argv[2])
        case _:
            print(__doc__)
            sys.exit(1)