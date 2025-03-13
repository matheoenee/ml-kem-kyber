# kyber/cryptographic.py

import hashlib

def PRF(s: bytes, b: bytes, eta: int) -> bytes:
    """
    Description : The function PRF is used to sampling polynomial coefficients from the center binomial distribution using SHAKE-256.

    Input:
        eta (int): Specify output length.
        s (bytes): Random 32-byte.
        b (bytes): Random 1-byte.

    Output:
        h (bytes): Random (64*eta)-byte.
    """
    shake = hashlib.shake_256()
    shake.update(s+b)
    return shake.digest(64*eta)

def H(s: bytes) -> bytes:
    """
    Description : H is the hash function SHA3-256.

    Input:
        s (bytes): Random byte.

    Output:
        h (bytes): Random 32-byte.
    """
    return hashlib.sha3_256(s).digest()

def G(c: bytes):
    """
    Description : G is the hash function SHA3-512.

    Input:
        s (bytes): Random byte.

    Output:
        a (bytes): Random 32-byte.
        b (bytes): Random 32-byte.
    """
    d = hashlib.sha3_512(c).digest()
    return d[:32], d[32:]

def KDF(s: bytes, l: int) -> bytes:
    """
    Description : Key Derivation Function (KDF) using SHAKE256.

    Input:
        s (bytes): Random byte.
        l (int): Output length

    Output:
        K (bytes): Random l-byte.
    """
    shake = hashlib.shake_256()
    shake.update(s)
    return shake.digest(l)
