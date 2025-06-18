#!/usr/bin/env python3
"""
CCA2 Bit-Oracle Attack Demo ‒ OAEP-hardened version
===================================================

This script maintains the behavior and output file format of the "setup / attack" subcommands,
but internally replaces all RSA calls with the RSA-OAEP scheme from `rsa_oaep_assignment.py`
(1024 bit, SHA-512, k₀ = 64 B, k₁ = 1 B).

* ``python cca2_attack_demo.py setup``  
    – Acts as **victim client**:  
      Generates AES-128 session key → RSA encrypts with OAEP encoding → writes
      History_Message.txt and other auxiliary files.

* ``python cca2_attack_demo.py attack``  
    – Acts as **active attacker**:  
      Preserves the original 128-bit oracle CCA2 attack logic (now ineffective against OAEP,
      but code unchanged, just demonstrating the "attack failure" effect).

Dependency: ``pycryptodome`` (`pip install pycryptodome`)
"""

from __future__ import annotations

import json
import os
import random
import sys
import time
from typing import Tuple

from Crypto.Cipher import AES  # type: ignore
from Crypto.Util.Padding import pad, unpad

# ---- Key: Changed to import OAEP related functions ---------------------------------
from rsa_oaep_assignment import (
    oaep_encode,
    oaep_decode,
    rsa_enc_int,
    rsa_dec_int,
    int_from_bytes,
    int_to_bytes,
    MOD_BYTES,       # 128 B (1024-bit modulus size)
)

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def read_int(path: str) -> int:
    """Read a decimal integer from a text file."""
    return int(open(path, "r").read().strip())


def aes_encrypt_ecb(key: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(pad(data, 16))


def aes_decrypt_ecb(key: bytes, ct: bytes) -> bytes:
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), 16)


# ------------------------------------------------------------
# Oracle (simulated server)
# ------------------------------------------------------------

class Oracle:
    """Simulates server-side logic (now using OAEP instead of raw RSA).

    *   Uses RSA-OAEP to decrypt ciphertext, obtaining the original 16 B AES session key.
    *   Attempts AES-ECB decryption with this key to verify if JSON is valid.
    *   Returns *True* if parsing succeeds (≙ "server returns 200 OK").
    """

    def __init__(self, d: int, n: int):
        self.d = d
        self.n = n

    def query(self, C_prime: int, aes_ct_hex: str) -> bool:
        # 1. RSA-OAEP 解密
        m_int = rsa_dec_int(C_prime, self.d, self.n)
        em_bytes = int_to_bytes(m_int, MOD_BYTES)           # 128 B
        try:
            k_bytes = oaep_decode(em_bytes)                 # 原始 16 B 会话密钥
            if len(k_bytes) != 16:
                raise ValueError("OAEP-decoded length mismatch")
        except Exception:
            return False

        # 2. AES 解密 + JSON 校验
        try:
            pt = aes_decrypt_ecb(k_bytes, bytes.fromhex(aes_ct_hex))
            json.loads(pt.decode())  # raise if not valid UTF-8 / JSON
            return True
        except Exception:
            return False


# ------------------------------------------------------------
# Victim-client setup phase
# ------------------------------------------------------------

def setup_phase() -> None:
    print("[SETUP] Loading RSA parameters …")
    n = read_int("RSA_Moduler.txt")
    e = read_int("RSA_Public_Key.txt")

    # 1. Generate AES-128 session key (using current millisecond time as seed, maintaining original logic)
    seed_ms = int(time.time() * 1000)
    rng = random.Random(seed_ms)
    k_int = rng.getrandbits(128)
    k_bytes = k_int.to_bytes(16, "big")
    print(f"[SETUP] AES key (from PRNG seeded {seed_ms}):", k_bytes.hex())

    # 2. Construct minimal WUP request
    wup_obj = {
        "imei": "990000862471854",
        "url": "https://example.com",
        "ts": int(time.time())
    }
    wup_plain = json.dumps(wup_obj, separators=(",", ":")).encode()
    wup_ct = aes_encrypt_ecb(k_bytes, wup_plain)

    # 3. Encrypt AES key with RSA-OAEP
    em_bytes, _r = oaep_encode(k_bytes)         # OAEP encoding → 128 B
    # print(f"em_bytes: {em_bytes}")
    # print(f"int_from_bytes: {int_from_bytes(em_bytes)}")
    C_int = rsa_enc_int(int_from_bytes(em_bytes), e, n)

    # 4. Write files compatible with scoring script
    open("AES_Key.txt", "w").write(k_bytes.hex())
    open("WUP_Request.txt", "w").write(wup_plain.hex())
    open("AES_Encrypted_WUP.txt", "w").write(wup_ct.hex())
    with open("History_Message.txt", "w") as f:
        f.write(hex(C_int)[2:] + "\n" + wup_ct.hex())

    print("[SETUP] Files generated: History_Message.txt etc.")


# ------------------------------------------------------------
# CCA2 attack phase (logic unchanged – 对 OAEP 将失效)
# ------------------------------------------------------------

def attack_phase() -> None:
    print("[ATTACK] Loading data …")
    n = read_int("RSA_Moduler.txt")
    e = read_int("RSA_Public_Key.txt")
    d = read_int("RSA_Secret_Key.txt")

    with open("History_Message.txt", "r") as f:
        C_hex = f.readline().strip()
        victim_ct_hex = f.readline().strip()
    C_orig = int(C_hex, 16)

    oracle = Oracle(d, n)

    # Constant WUP plaintext – same as original script
    attack_wup_plain = b"{\"ok\":true}"

    # Precompute 2^e (mod n)
    two_pow_e_mod_n = pow(2, e, n)

    recovered_bits = 0
    print("[ATTACK] Starting 128-query bit-oracle attack …")

    queries = 0
    for i in range(128):
        b_shift = 127 - i
        C_b = (C_orig * pow(two_pow_e_mod_n, b_shift, n)) % n

        # ---- guess 0 ----
        k_guess0 = recovered_bits
        stub0 = ((k_guess0) << b_shift) & ((1 << 128) - 1)
        ct0_hex = aes_encrypt_ecb(stub0.to_bytes(16, "big"), attack_wup_plain).hex()
        success = oracle.query(C_b, ct0_hex)
        queries += 1

        if success:
            bit = 0
        else:
            bit = 1
            recovered_bits |= 1 << i
        print(f"    recovered k[{i:3}] = {bit}")

    recovered_key_bytes = recovered_bits.to_bytes(16, "big")
    print("[ATTACK] Recovered AES key (expected to be WRONG with OAEP):",
          recovered_key_bytes.hex())
    open("Recovered_AES_Key.txt", "w").write(recovered_key_bytes.hex())

    # Try to decrypt with "recovered" key (should fail)
    try:
        wup_plain = aes_decrypt_ecb(recovered_key_bytes, bytes.fromhex(victim_ct_hex))
        print("[ATTACK] Decrypted victim WUP →", wup_plain.decode())
    except Exception as exc:
        print("[ATTACK] Verification failed (as intended):", exc)

    print("[ATTACK] Total oracle queries:", queries)


# ------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"setup", "attack"}:
        print("Usage: python cca2_attack_demo.py [setup|attack]")
        sys.exit(1)

    if sys.argv[1] == "setup":
        setup_phase()
    else:
        attack_phase()
