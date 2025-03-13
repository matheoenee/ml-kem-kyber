# ml_kem/params.py

# Global constants
n = 256  # Fixed polynomial size
q = 3329 # Prime modulus

class MLKEMParams:
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
MLKEM512 = MLKEMParams(k=2, eta1=3, eta2=2, du=10, dv=4)
MLKEM768 = MLKEMParams(k=3, eta1=2, eta2=2, du=10, dv=4)
MLKEM1024 = MLKEMParams(k=4, eta1=2, eta2=2, du=11, dv=5)

# Dictionary to access parameter sets easily
MLKEM_PARAM_SETS = {
    "MLKEM512": MLKEM512,
    "MLKEM768": MLKEM768,
    "MLKEM1024": MLKEM1024
}