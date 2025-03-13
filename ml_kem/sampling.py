# ml-kem/sampling.py

import hashlib, math

from ml_kem.conversion import BytesToBits
from . import n, q

def SampleNTT(B: bytes) -> list[int]:
    """
    Description:
        Samples a polynomial in the Number Theoretic Transform (NTT) domain from a byte string using SHAKE-128.
        It extracts coefficients in a rejection sampling manner to ensure they are within the modulus q.

    Input:
        B (bytes): Input byte string used as a seed for SHAKE-128.

    Output:
        a (list[int]): A polynomial of length n with coefficients in the range [0, q-1].
    """
    shake = hashlib.shake_128()
    shake.update(B)
    cnt = 1
    j = 0
    a = [0] * n 
    while j<n:
        digest = shake.digest(cnt*3)
        C = digest[-3:]
        d1 = C[0] + (n * (C[1] % 16))
        d2 = math.floor(C[1]/16) + 16*C[2]
        if d1 < q:
            a[j] = d1
            j += 1
        if d2 < q and j < n:
            a[j] = d2
            j += 1
        cnt += 1
    return a

def SamplePolyCBD(B: bytes, eta: int) -> list[int]:
    """
    Description:
        Samples a polynomial from a Centered Binomial Distribution (CBD) using a bit string. It computes coefficients as differences between two sums of bits extracted from B.

    Input:
        B (bytes): Input byte string used to generate polynomial coefficients.
        eta (int): Parameter controlling the variance of the binomial distribution.

    Output:
        f (list[int]): A polynomial of length n with coefficients in the range [-η, η] mod q.
    """
    b = BytesToBits(B)
    f = [0] * n
    for i in range(n):
        x = 0
        y = 0
        for j in range(eta):
            x += b[2*i*eta + j]
            y += b[2*i*eta + eta + j]
        f[i] = x - y % q
    return f