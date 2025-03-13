import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml_kem.kem import KEM_KeyGen, KEM_Encaps, KEM_Decaps
from ml_kem.params import *

# Initialize default parameters (adjust if needed)
params = MLKEM512

def test_ml_kem():
    print("Testing ML-KEM Implementation...\n")

    # Step 1: Generate Keypair
    print("[1] Generating keypair...")
    ek, dk = KEM_KeyGen(params)
    print("   - Public Key:", ek.hex()[:64], "...")  # Show first part for readability
    print("   - Private Key:", dk.hex()[:64], "...")

    # Step 2: Encapsulate a shared secret
    print("\n[2] Encapsulating shared secret...")
    K, c = KEM_Encaps(ek, params)
    print("   - Encapsulated Secret:", K.hex()[:64], "...")
    print("   - Ciphertext:", c.hex()[:64], "...")

    # Step 3: Decapsulate and verify correctness
    print("\n[3] Decapsulating shared secret...")
    K_prime = KEM_Decaps(dk, c, params)
    print("   - Decapsulated Secret:", K_prime.hex()[:64], "...")

    # Step 4: Check if decryption is correct
    if K == K_prime:
        print("\nTest Passed: Shared secret matches!")
    else:
        print("\nTest Failed: Shared secret does NOT match!")

if __name__ == "__main__":
    test_ml_kem()