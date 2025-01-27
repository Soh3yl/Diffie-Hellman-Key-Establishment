import secrets
import hashlib

class DiffieHellmanKeyExchange:
 
    @staticmethod
    def generate_large_prime(bits=512):

        while True:
            # Generate a random number of the specified bit length
            candidate = secrets.randbits(bits)
            
            # Ensure the number is odd and meets minimum bit requirements
            candidate |= (1 << (bits - 1)) | 1
            
            # Use a probabilistic primality test (Miller-Rabin)
            if DiffieHellmanKeyExchange._is_prime(candidate):
                return candidate
    
    @staticmethod
    def _is_prime(n, k=40):

        if n <= 1 or n == 4:
            return False
        if n <= 3:
            return True
        
        # Write n as 2^r * d + 1
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Witness loop
        for _ in range(k):
            a = secrets.randbelow(n - 4) + 2
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            is_composite = True
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    is_composite = False
                    break
            
            if is_composite:
                return False
        
        return True
    
    def __init__(self, prime=None, generator=None):

        # Use a default large prime if not provided
        self.prime = prime or self.generate_large_prime()
        
        # Use a secure generator (typically a small prime number)
        self.generator = generator or 2
        
        # Generate a cryptographically secure private key
        self.private_key = secrets.randbelow(self.prime - 2) + 1
        
        # Compute public key
        self.public_key = pow(self.generator, self.private_key, self.prime)
    
    def compute_shared_secret(self, other_public_key):

        # Compute shared secret
        shared_secret = pow(other_public_key, self.private_key, self.prime)
        
        # Hash the shared secret for additional security
        return hashlib.sha256(str(shared_secret).encode()).digest()