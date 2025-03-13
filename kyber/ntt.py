# kyber/ntt.py

from kyber.utils import BitRev7, TwoBitRev7Plus1
from . import q, n

def NTT(f: list[int]) -> list[int]:
    """
    Description:
        Computes the Number Theoretic Transform (NTT) of a polynomial in the coefficient representation.

    Input:
        f (list[int]): A polynomial of length 256 with integer coefficients modulo q.

    Output:
        f_ntt (list[int]): The transformed polynomial in the NTT domain.
    """
    f_ntt = f
    i = 1
    length = 128
    while length >= 2:
        start = 0
        while start < n:
            zeta = BitRev7[i] % q
            i += 1
            for j in range(start, start+length, 1):
                t = (zeta * f_ntt[j+length]) % q
                f_ntt[j+length] = (f_ntt[j] - t) % q
                f_ntt[j] = (f_ntt[j] + t) % q
            start += 2*length
        length //= 2 
    return f_ntt

def inv_NTT(f_ntt: list[int]) -> list[int]:
    """
    Description:
        Computes the inverse Number Theoretic Transform (NTT), converting a polynomial from the NTT domain back to its coefficient representation.

    Input:
        f_ntt (list[int]): A polynomial of length 256 in the NTT domain.

    Output:
        f (list[int]): The polynomial transformed back into the coefficient domain modulo q.
    """
    f = f_ntt
    i = 127
    length = 2
    while length <= 128:
        start = 0
        while start < n:
            zeta = BitRev7[i] % q
            i -= 1
            for j in range(start, start+length, 1):
                t = f[j] % q
                f[j] = (t + f[j+length]) % q
                f[j+length] = (zeta * (f[j+length]-t)) % q
            start += 2*length 
        length *= 2
    for i in range(n):
        f[i] = (f[i]*3303) % q
    return f

def BaseCaseMultiply(a0: int, a1: int, b0: int, b1:int , gamma: int) -> list[int]:
    """
    Performs the base case multiplication for the Number Theoretic Transform (NTT).

    Input:
        a0 (int): First coefficient of the first operand.
        a1 (int): Second coefficient of the first operand.
        b0 (int): First coefficient of the second operand.
        b1 (int): Second coefficient of the second operand.
        gamma (int): A quadratic modulus.

    Output:
        list: A list of two integers [c0, c1] representing the result of the multiplication modulo q.
    """
    c = [0] * 2
    c[0] = (a0*b0 + a1*b1*gamma) % q
    c[1] = (a0*b1 + a1*b0) % q
    return c

def MultiplyNTTs(f: list[int], g: list[int]) -> list[int]:
    """
    Multiplies two NTT-transformed polynomials element-wise using the base case multiplication.

    Input:
        f (list): The first NTT-transformed polynomial.
        g (list): The second NTT-transformed polynomial.

    Output:
        list: The element-wise product of `f` and `g` in the NTT domain.
    """
    h = [0] * n
    for i in range(128):
        h[2*i],h[2*i+1] = BaseCaseMultiply(f[2*i], f[2*i+1], g[2*i], g[2*i+1], TwoBitRev7Plus1[i])
    return h