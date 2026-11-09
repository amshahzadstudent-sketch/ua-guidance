"""
IDEA (International Data Encryption Algorithm) written from scratch.

    - symmetric block cipher: the same key encrypts and decrypts
    - 128-bit key, 64-bit blocks, 8 rounds + 1 output step
    - mixes XOR, addition mod 2^16 and multiplication mod 2^16 + 1

Wrapped for real use with:
    CBC mode    - chains blocks so data of any length is protected
    PKCS7       - pads the last block to 8 bytes
    HMAC-SHA256 - IDEA has no tamper check of its own, so a MAC seal is added
                  (encrypt-then-MAC). Any change to stored data is detected.
"""
import hashlib
import hmac
import os
from typing import List, Tuple

MASK = 0xFFFF  # IDEA works on 16-bit words


def mul(a: int, b: int) -> int:
    """Multiply modulo 65537 (a prime). The value 0 stands for 2^16."""
    a, b = a or 0x10000, b or 0x10000
    return (a * b) % 0x10001 & MASK


def mul_inv(x: int) -> int:
    """Multiplicative inverse modulo 65537 (for decryption keys)."""
    return x if x <= 1 else pow(x, -1, 0x10001)


def add_inv(x: int) -> int:
    """Additive inverse modulo 65536 (for decryption keys)."""
    return (-x) & MASK


def expand_key(key: bytes) -> List[int]:
    """KEY SCHEDULE: 128-bit key -> 52 sixteen-bit subkeys. The key is split
    into 8 subkeys, rotated left 25 bits, split again, until 52 exist."""
    assert len(key) == 16, "IDEA needs a 128-bit key"
    k, sub = int.from_bytes(key, "big"), []
    while len(sub) < 52:
        sub += [(k >> (112 - 16 * i)) & MASK for i in range(8)]
        k = ((k << 25) | (k >> 103)) & ((1 << 128) - 1)
    return sub[:52]


def invert_key(ek: List[int]) -> List[int]:
    """DECRYPTION KEY SCHEDULE: the same circuit with inverted subkeys."""
    dk = [mul_inv(ek[48]), add_inv(ek[49]), add_inv(ek[50]), mul_inv(ek[51])]
    for i in range(7, -1, -1):
        k = 6 * i
        dk += [ek[k + 4], ek[k + 5]]
        t1, t2, t3, t4 = mul_inv(ek[k]), add_inv(ek[k + 1]), add_inv(ek[k + 2]), mul_inv(ek[k + 3])
        dk += [t1, t3, t2, t4] if i > 0 else [t1, t2, t3, t4]  # middle swap
    return dk


def crypt_block(block: bytes, sk: List[int]) -> bytes:
    """Run ONE 64-bit block through IDEA (encrypts or decrypts, depending on
    whether the normal or the inverted subkeys are passed in)."""
    x1, x2, x3, x4 = [int.from_bytes(block[i:i + 2], "big") for i in (0, 2, 4, 6)]
    for r in range(8):
        k = sk[6 * r:6 * r + 6]
        x1, x2, x3, x4 = mul(x1, k[0]), (x2 + k[1]) & MASK, (x3 + k[2]) & MASK, mul(x4, k[3])
        t2 = mul(x1 ^ x3, k[4])                       # multiplication-addition
        t1 = mul((t2 + (x2 ^ x4)) & MASK, k[5])       # structure
        t2 = (t1 + t2) & MASK
        x1, x4 = x1 ^ t1, x4 ^ t2
        t2 ^= x2
        x2, x3 = x3 ^ t1, t2
    y = [mul(x1, sk[48]), (x3 + sk[49]) & MASK, (x2 + sk[50]) & MASK, mul(x4, sk[51])]
    return b"".join(v.to_bytes(2, "big") for v in y)


def derive_keys(master: bytes) -> Tuple[bytes, bytes]:
    """KEY GENERATION: split the server's 32-byte master key into a 128-bit
    IDEA key and a separate 256-bit HMAC key (never reuse one key for both)."""
    return (hmac.new(master, b"idea-key", hashlib.sha256).digest()[:16],
            hmac.new(master, b"mac-key", hashlib.sha256).digest())


def seal(master: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """ENCRYPT: returns iv(8) + ciphertext + mac(32).
    1. random 8-byte IV; 2. PKCS7 padding; 3. CBC: each block is XORed with
    the previous ciphertext block, then encrypted by IDEA; 4. HMAC-SHA256 over
    (aad + iv + ciphertext). aad = reference code: not hidden, but a record
    cannot be moved to another appointment without detection."""
    enc_key, mac_key = derive_keys(master)
    sk, iv = expand_key(enc_key), os.urandom(8)
    n = 8 - len(plaintext) % 8
    data, prev, out = plaintext + bytes([n]) * n, iv, b""
    for i in range(0, len(data), 8):
        prev = crypt_block(bytes(a ^ b for a, b in zip(data[i:i + 8], prev)), sk)
        out += prev
    return iv + out + hmac.new(mac_key, aad + iv + out, hashlib.sha256).digest()


def unseal(master: bytes, blob: bytes, aad: bytes) -> bytes:
    """DECRYPT: check the HMAC seal FIRST; raise ValueError if the key is
    wrong or ANY byte was changed. Then reverse CBC with the inverted subkeys."""
    enc_key, mac_key = derive_keys(master)
    if len(blob) < 8 + 8 + 32 or (len(blob) - 40) % 8:
        raise ValueError("integrity check failed")
    iv, ct, mac = blob[:8], blob[8:-32], blob[-32:]
    if not hmac.compare_digest(mac, hmac.new(mac_key, aad + iv + ct, hashlib.sha256).digest()):
        raise ValueError("integrity check failed")
    dk, prev, out = invert_key(expand_key(enc_key)), iv, b""
    for i in range(0, len(ct), 8):
        out += bytes(a ^ b for a, b in zip(crypt_block(ct[i:i + 8], dk), prev))
        prev = ct[i:i + 8]
    return out[:-out[-1]]
