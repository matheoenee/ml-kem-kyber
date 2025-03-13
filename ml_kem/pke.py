# ml-kem/pke.py

from ml_kem.sampling import SampleNTT, SamplePolyCBD
from ml_kem.cryptographic import PRF, G
from ml_kem.ntt import NTT, inv_NTT, MultiplyNTTs
from ml_kem.polynomials import AddPolynomials, SubPolynomials
from ml_kem.conversion import ByteDecode, ByteEncode, Compress, Decompress

from ml_kem.params import *
from . import q, n

def PKE_KeyGen(d: bytes, params: MLKEMParams) -> list[bytes]:
    """
    Generate the public/private pair of keys for the ML-KEM Public Key Encryption (PKE) scheme.

    Inputs:
        ek_pke (bytes): The public encryption key.
        m (bytes): The 32-bytes plaintext.
        r (bytes): Random 32-byte
        params (MLKEMParams): An object containing Kyber parameter values, including:
            - k (int): Number of polynomials in the key.
            - eta1 (int): Noise parameter.

    Output:
        list[bytes]: The pulbic encryption and private decryption keys.
    """
    k = params.k
    eta1 = params.eta1
    
    rho, sigma = G(d + bytes([k]))

    N = 0
    A_ntt = [[0] * k for _ in range(k)]
    for i in range(k):
        for j in range(k):
            A_ntt[i][j] = SampleNTT(rho + bytes([j]) + bytes([i]))
    
    s_ntt = [0] * k
    for i in range(k):
        s = SamplePolyCBD(PRF(sigma, bytes([N]), eta1), eta1)
        s_ntt[i] = NTT(s)
        N += 1

    e_ntt = [0] * k
    for i in range(k):
        e = SamplePolyCBD(PRF(sigma, bytes([N]), eta1), eta1)
        e_ntt[i] = NTT(e)
        N += 1

    t_ntt = [0] * k
    for i in range(k):
        sum = [0] * 256
        for j in range(k):
            prod = MultiplyNTTs(A_ntt[i][j], s_ntt[j])
            sum = AddPolynomials(sum, prod)
        t_ntt[i] = AddPolynomials(sum, e_ntt[i])

    ek_pke = b""
    dk_pke = b""
    for i in range(k):
        ek_pke += ByteEncode(t_ntt[i], 12)
        dk_pke += ByteEncode(s_ntt[i], 12)
    ek_pke += rho
    return ek_pke, dk_pke

def PKE_Encrypt(ek_pke: bytes, m: bytes, r: bytes, params: MLKEMParams) -> bytes:
    """
    Encrypts a plaintext using the public encryption key in the ML-KEM Public Key Encryption (PKE) scheme.

    Inputs:
        ek_pke (bytes): The public encryption key.
        m (bytes): The 32-bytes plaintext.
        r (bytes): Random 32-byte
        params (MLKEMParams): An object containing Kyber parameter values, including:
            - k (int): Number of polynomials in the key.
            - eta1 (int): Noise parameter.
            - eta2 (int): Noise parameter.
            - du (int): Compression parameter for `u'`.
            - dv (int): Compression parameter for `v'`.

    Output:
        bytes: The encrypted message.
    """
    k = params.k
    eta1 = params.eta1
    eta2 = params.eta2
    du = params.du
    dv = params.dv

    N = 0
    t_ntt = [0] * k
    for i in range(k):
        t_ntt[i] = ByteDecode(ek_pke[384*i : 384*i + 384], 12)
    
    rho = ek_pke[384*k :]

    A_ntt = [[0] * k for _ in range(k)]
    for i in range(k):
        for j in range(k):
            A_ntt[i][j] = SampleNTT(rho + bytes([j]) + bytes([i]))

    y_ntt = [0] * k
    for i in range(k):
        y = SamplePolyCBD(PRF(r, bytes([N]), eta1), eta1)
        y_ntt[i] = NTT(y)
        N += 1

    e1 = [0] * k
    for i in range(k):
        e1[i] = SamplePolyCBD(PRF(r, bytes([N]), eta2), eta2)
        N += 1

    e2 = SamplePolyCBD(PRF(r, bytes([N]), eta2), eta2)
    
    u = [0] * k
    for i in range(k):
        sum_ntt = [0] * n
        for j in range(k):
            prod = MultiplyNTTs(A_ntt[j][i], y_ntt[j]) # transpose A good?
            sum_ntt = AddPolynomials(sum_ntt, prod)
        u[i] = AddPolynomials(inv_NTT(sum_ntt), e1[i])

    mu = [0] * n
    m_decode = ByteDecode(m, 1)
    for i in range(n):
        mu[i] = Decompress(m_decode[i], 1)
    
    sum_ntt = [0] * n
    for i in range(k):
        prod = MultiplyNTTs(t_ntt[i], y_ntt[i])
        sum_ntt = AddPolynomials(sum_ntt, prod)
    v = AddPolynomials(inv_NTT(sum_ntt), e2)
    v = AddPolynomials(v, mu)

    c1 = b""
    for i in range(k):
        u_compress = [0] * n
        for j in range(n):
            u_compress[j] = Compress(u[i][j], du)
        c1 += ByteEncode(u_compress, du)
    
    
    v_compress = [0] * n
    for i in range(n):
        v_compress[i] = Compress(v[i], dv)
    c2 = ByteEncode(v_compress, dv)

    return c1 + c2

def PKE_Decrypt(dk_pke: bytes, c: bytes, params: MLKEMParams) -> bytes:
    """
    Decrypts a ciphertext using the private decryption key in the ML-KEM Public Key Encryption (PKE) scheme.

    Inputs:
        dk_pke (bytes): The private decryption key.
        c (bytes): The ciphertext.
        params (MLKEMParams): An object containing Kyber parameter values, including:
            - k (int): Number of polynomials in the key.
            - du (int): Compression parameter for `u'`.
            - dv (int): Compression parameter for `v'`.

    Output:
        bytes: The decrypted message.
    """
    k = params.k
    du = params.du
    dv = params.dv
    
    c1 = c[:32*du*k]
    c2 = c[32*du*k:]

    u_prime = [[0] * n for _ in range(k)]
    for i in range(k):
        c1_decode = ByteDecode(c1[32*du*i : 32*du*i + 32*du], du)
        for j in range(n):
            u_prime[i][j] = Decompress(c1_decode[j], du)
    
    v_prime = [0] * n
    c2_decode = ByteDecode(c2, dv)
    for i in range(n):
        v_prime[i] = Decompress(c2_decode[i], dv)

    s_ntt = [0] * k
    for i in range(k):
        s_ntt[i] = ByteDecode(dk_pke[384*i : 384*i + 384], 12)

    u_prime_ntt = [0] * k 
    for i in range(k):
        u_prime_ntt[i] = NTT(u_prime[i])

    sum_ntt = [0] * n
    for i in range(k):
        m = MultiplyNTTs(s_ntt[i], u_prime_ntt[i])
        sum_ntt = AddPolynomials(sum_ntt, m)
    omega = SubPolynomials(v_prime, inv_NTT(sum_ntt))

    omega_compress = [0] * n
    for i in range(n):
        omega_compress[i] = Compress(omega[i], 1)
    m = ByteEncode(omega_compress, 1)

    return m