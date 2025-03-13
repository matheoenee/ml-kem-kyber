# kyber/params.py

# Global constants
n = 256  # Fixed polynomial size
q = 3329 # Prime modulus

class KYBERParams:
    """
    Stores parameters for different ML-KEM security levels.
    """
    def __init__(self, k, eta1, eta2, du, dv):
        self.k = k          # Dimension of the lattic
        self.eta1 = eta1    # Noise distribution parameter
        self.eta2 = eta2    # Noise distribution parameter 
        self.du = du        # Compression parameter for ciphertext 
        self.dv = dv        # Compression parameter for ciphertext

# Define the three ML-KEM variants
KYBER512 = KYBERParams(k=2, eta1=3, eta2=2, du=10, dv=4)
KYBER768 = KYBERParams(k=3, eta1=2, eta2=2, du=10, dv=4)
KYBER1024 = KYBERParams(k=4, eta1=2, eta2=2, du=11, dv=5)

# Dictionary to access parameter sets easily
KYBER_PARAM_SETS = {
    "KYBER512": KYBER512,
    "KYBER768": KYBER768,
    "KYBER1024": KYBER1024
}