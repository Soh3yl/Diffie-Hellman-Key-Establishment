import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Diffie_Hellman_Key_Exchange.DiffieHellmanKeyExchange import DiffieHellmanKeyExchange

def demonstrate_key_exchange():

    print("Diffie-Hellman Key Exchange Demonstration:")
    
    # Alice generates her key exchange instance
    alice = DiffieHellmanKeyExchange()
    print(f"Alice's Public Key: {alice.public_key}")
    
    # Bob generates his key exchange instance
    bob = DiffieHellmanKeyExchange(
        prime=alice.prime,  # Use the same prime
        generator=alice.generator  # Use the same generator
    )
    print(f"Bob's Public Key: {bob.public_key}")
    
    # Exchange public keys
    alice_shared_secret = alice.compute_shared_secret(bob.public_key)
    bob_shared_secret = bob.compute_shared_secret(alice.public_key)
    
    # Verify shared secrets are identical
    print("\nShared Secret Verification:")
    print(f"Alice's Shared Secret: {alice_shared_secret.hex()}")
    print(f"Bob's Shared Secret:   {bob_shared_secret.hex()}")
    print(f"Secrets Match: {alice_shared_secret == bob_shared_secret}")

if __name__ == "__main__":
    demonstrate_key_exchange()