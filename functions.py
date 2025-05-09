import random
import base64
import hashlib

def is_prime(n: int, k: int = 5) -> bool:
    """https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Complexity"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

def generate_large_prime(bits: int = 1024) -> int:
    """Generate probable prime with specified bit length"""
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1
        if is_prime(p):
            return p
        
def find_primitive_root(p: int) -> int:
    """Find smallest primitive root modulo prime p"""
    if p == 2:
        return 1
    
    factors = set()
    phi = p - 1
    n = phi
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)

    for g in range(2, p):
        if all(pow(g, phi // factor, p) != 1 for factor in factors):
            return g
    raise ValueError("Primitive root not found")

class DiffieHellman:
    def __init__(self, key_bits: int = 2048, p: int = None, g: int = None):
        self.p = p if p else generate_large_prime(key_bits)
        self.g = g if g else find_primitive_root(self.p)
        self.private_key = random.randint(2, self.p - 2)
        self.public_key = pow(self.g, self.private_key, self.p)

    def generate_shared_secret(self, other_public: int) -> int:
        """Compute shared secret using peer's public key"""
        if not 2 <= other_public <= self.p - 2:
            raise ValueError("Invalid public key")
        return pow(other_public, self.private_key, self.p)
    
def int_to_b64(num: int) -> str:
    """Convert integer to Base64 URL-safe string"""
    byte_length = (num.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(num.to_bytes(byte_length, 'big')).decode()

def b64_to_int(b64_str: str) -> int:
    """Convert Base64 string back to integer"""
    return int.from_bytes(base64.urlsafe_b64decode(b64_str), 'big')

def generate_keystream(shared_secret: int, length: int) -> bytes:
    """Generate pseudorandom keystream from shared secret"""
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    return hashlib.shake_128(secret_bytes).digest(length)

def xor_encrypt(plaintext: bytes, keystream: bytes) -> bytes:
    """XOR plaintext with keystream"""
    return bytes(pt ^ ks for pt, ks in zip(plaintext, keystream))

def encrypt_message(message: str, shared_secret: int) -> str:
    """Encrypt message to Base64 ciphertext"""
    plainbytes = message.encode('utf-8')
    keystream = generate_keystream(shared_secret, len(plainbytes))
    cipherbytes = xor_encrypt(plainbytes, keystream)
    return base64.urlsafe_b64encode(cipherbytes).decode()

def decrypt_message(ciphertext: str, shared_secret: int) -> str:
    """Decrypt Base64 ciphertext to plaintext"""
    cipherbytes = base64.urlsafe_b64decode(ciphertext)
    keystream = generate_keystream(shared_secret, len(cipherbytes))
    plainbytes = xor_encrypt(cipherbytes, keystream)
    return plainbytes.decode('utf-8')