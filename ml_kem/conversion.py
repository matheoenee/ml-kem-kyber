# ml-kem/conversion.py

import math
from . import q, n

def Compress(x: int, d: int) -> int:
    """
    Description: Compresses an integer x modulo q to d-bit precision.

    Input:
        x (int): Integer to be compressed.
        d (int): Number of bits for compression.

    Output:
        (int): Compressed integer.
    """
    return round((2**d/q) * x) % 2**d

def Decompress(y:int , d:int) -> int:
    """
    Description: Decompresses a d-bit integer back to approximate its original value modulo q.

    Input:
        y (int): Compressed integer.
        d (int): Number of bits used for compression.

    Output:
        (int): Decompressed integer.
    """
    return round(q/2**d * y)

def BitsToBytes(b: list[int]) -> bytes:
    """
    Description: Converts a list of bits into a byte array.

    Input:
        b (list[int]): List of bits (0s and 1s).

    Output:
        (bytes): Corresponding byte array.
    """
    l = int(len(b)/8)
    B = [0] * l
    for i in range(len(b)):
        B[math.floor(i/8)] = B[math.floor(i/8)] + b[i]*2**(i%8)
    return bytes(B)

def BytesToBits(B: bytes) -> list[int]:
    """
    Description: Converts a byte array into a list of bits.

    Input:
        B (bytes): Byte array to be converted.

    Output:
        (list[int]): Corresponding list of bits.
    """
    B = list(B)
    l = len(B)
    C = list(B)
    b = [0] * (l*8)
    for i in range(l):
        for j in range(8):
            b[i*8 + j] = C[i] % 2
            C[i] = math.floor(C[i]/2)  
    return b
    
def ByteEncode(F: list[int], d: int) -> bytes:
    """
    Description: Encodes a list of integers into bytes using d-bit encoding.

    Input:
        F (list[int]): List of integers to encode.
        d (int): Number of bits per integer.

    Output:
        (bytes): Encoded byte representation.
    """
    b = [0] * (n * d)
    for i in range(n):
        a = F[i]
        for j in range(d):
            b[i*d + j] = int(a % 2)
            a = (a - b[i*d + j]) / 2  
    B = BitsToBytes(b) 
    return B

def ByteDecode(B: bytes, d: int) -> list[int]:
    """
    Description: Decodes bytes back into a list of integers using d-bit decoding.

    Input:
        B (bytes): Encoded byte representation.
        d (int): Number of bits per integer.

    Output:
        (list[int]): Decoded list of integers.
    """
    m = q if d == 12 else 2**d
    
    b = BytesToBits(B)
    F = [0] * n
    for i in range(n):
        sum = 0
        for j in range(d):
            sum = sum + b[i*d + j] * 2**j % m
        F[i] = int(sum)
    return F