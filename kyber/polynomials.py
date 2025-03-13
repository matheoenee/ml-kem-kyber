# kyber/polynomials.py

from . import q, n

def AddPolynomials(a: list[int], b: list[int]) -> list[int]:
     """
    Adds two polynomials coefficient-wise modulo q.

    Input:
        a (list): A polynomial represented as a list of 256 coefficients.
        b (list): Another polynomial represented as a list of 256 coefficients.

    Output:
        list: A polynomial where each coefficient is the sum of corresponding coefficients in `a` and `b`, modulo q.
    """
     return [(a[i] + b[i]) % q for i in range(n)]

def SubPolynomials(a: list[int], b: list[int]) -> list[int]:
     """
    Subtracts one polynomial from another coefficient-wise modulo q.

    Input:
        a (list): A polynomial represented as a list of 256 coefficients.
        b (list): Another polynomial represented as a list of 256 coefficients.

    Output:
        list: A polynomial where each coefficient is the difference of corresponding coefficients in `a` and `b`, modulo q.
    """
     return [(a[i] - b[i]) % q for i in range(n)]