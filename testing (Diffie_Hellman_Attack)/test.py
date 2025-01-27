import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Diffie_Hellman_Key_Exchange.DiffieHellmanKeyExchange import DiffieHellmanKeyExchange
from Diffie_Hellman_Attack.DiffieHellmanAttack import meet_in_the_middle_attack

# Example usage
prime = 23  # Small prime for demonstration
generator = 5  # Small generator for demonstration

# Generate keys for Alice and Bob
alice = DiffieHellmanKeyExchange(prime, generator)
bob = DiffieHellmanKeyExchange(prime, generator)
print(f"Alice's Public Key: {alice.public_key}")
print(f"Bob's Public Key: {bob.public_key}")

# Perform Meet-in-the-Middle attack
shared_secrets = meet_in_the_middle_attack(prime, generator, alice.public_key, bob.public_key)

if shared_secrets:
    print("Shared secrets found:")
    print("Shared secret (Alice):", shared_secrets[0])
    print("Shared secret (Bob):", shared_secrets[1])
else:
    print("No shared secret found!")