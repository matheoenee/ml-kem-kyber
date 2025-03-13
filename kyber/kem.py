# kyber/kem.py

import secrets

from kyber.pke import PKE_KeyGen, PKE_Encrypt, PKE_Decrypt
from kyber.cryptographic import H, G, KDF
from kyber.params import *

DEFAULT_PARAMS = KYBER768

def _KEM_KeyGen_internal(d: bytes, z: bytes, params: KYBERParams) -> list[bytes]:
    """
    Internal function to generates a Kyber KEM keypair.

    Inputs:
        d (bytes): Random seed used to generate key pairs.
        z (bytes): A 32-byte random value used for KEM key derivation.
        params (KYBERParams): Kyber parameters, including:
            - k (int): Number of polynomials in the key.

    Outputs:
        ek (bytes): The KEM public key.
        dk (bytes): The KEM private key.
    """
    k = params.k

    ek_pke, dk_pke = PKE_KeyGen(d, params)
    ek = ek_pke
    dk = dk_pke + ek + H(ek) + z
    return ek, dk

def _KEM_Encaps_internal(ek: bytes, m: bytes, params: KYBERParams) -> list[bytes]:
    """
    Internal function to encapsulate a secret key using the Kyber KEM.

    This function derives a shared secret `K` and randomness `r` from the plaintext `m` and the hash of the public key.
    It then encrypts `m` using the PKE encryption function to produce a ciphertext `c`.

    Inputs:
        ek (bytes): The KEM public key.
        m (bytes): The plaintext (usually a randomly generated key seed).
        params (KYBERParams): Kyber parameters, including:
            - k (int): Number of polynomials in the key.

    Outputs:
        K (bytes): The shared secret key.
        c (bytes): The ciphertext encapsulating `K`.
    """
    m = H(m)
    K_bar, r = G(m + H(ek))
    c = PKE_Encrypt(ek, m, r, params)
    K = KDF(K_bar + H(c), 32)
    return K, c

def _KEM_Decaps_internal(dk: bytes, c: bytes, params: KYBERParams) -> list[bytes]:
    """
    Internal function to decaspulate a ciphertext to retrieve the shared secret key.

    Inputs:
        dk (bytes): The KEM private key.
        c (bytes): The ciphertext encapsulating the shared secret.
        params (KYBERParams): Kyber parameters, including:
            - k (int): Number of polynomials in the key.

    Output:
        K (bytes): The shared secret key.
    """
    k = params.k

    dk_pke = dk[0 : 384*k]
    ek_pke = dk[384*k : 768*k+32]
    h = dk[768*k+32 : 768*k+64]
    z = dk[768*k+64 : 768*k+96]

    m_prime = PKE_Decrypt(dk_pke, c, params)
    K__bar_prime, r_prime = G(m_prime + h)

    c_prime = PKE_Encrypt(ek_pke, m_prime, r_prime, params)
    
    if c_prime == c:
        K = KDF(K__bar_prime + H(c), 32)
    else:
        K = KDF(z + H(c), 32)
    return K

def KEM_KeyGen(params: KYBERParams = DEFAULT_PARAMS) -> list[bytes]:
    """
    Generates a Kyber KEM keypair.

    Inputs:
        params (KYBERParams, optional): An object containing Kyber parameters such as:
            - k (int): Number of polynomials in the key.
            - eta1 (int): Noise parameter for key generation.
            - eta2 (int): Noise parameter for encryption.
            - du (int): Compression parameter for `u'`.
            - dv (int): Compression parameter for `v'`.
        Defaults to `DEFAULT_PARAMS`.

    Outputs:
        ek (bytes): The public key.
        dk (bytes): The private key.
    """
    d = secrets.token_bytes(32)
    z = secrets.token_bytes(32)
    if d is None or z is None:
        return None
    ek, dk = _KEM_KeyGen_internal(d, z, params) 
    return ek, dk

def KEM_Encaps(ek: bytes, params: KYBERParams = DEFAULT_PARAMS) -> list[bytes]:
    m = secrets.token_bytes(32)
    if m is None:
        return None
    K,c = _KEM_Encaps_internal(ek, m, params)
    return K, c

def KEM_Decaps(dk: bytes, c: bytes, params: KYBERParams = DEFAULT_PARAMS) -> bytes:
    K_prime = _KEM_Decaps_internal(dk, c, params)
    return K_prime