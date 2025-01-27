import hashlib

def meet_in_the_middle_attack(prime, generator, target_public_key_A, target_public_key_B):
    known_values = set()

    for private_key in range(1, 2**16):
        public_key_A = pow(generator, private_key, prime)
        known_values.add(public_key_A)

    for private_key in range(1, 2**16):
        public_key_B = pow(generator, private_key, prime)
        if public_key_B in known_values:
            shared_secret_A = pow(target_public_key_A, private_key, prime)
            shared_secret_B = pow(target_public_key_B, private_key, prime)
            hashed_secret_A = hashlib.sha256(str(shared_secret_A).encode()).digest()
            hashed_secret_B = hashlib.sha256(str(shared_secret_B).encode()).digest()
            return (hashed_secret_A, hashed_secret_B)