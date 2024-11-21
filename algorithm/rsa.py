import secrets
import math

class RSA:
    def __init__(self, bits):
        self.bits = bits
        self.p = self.generate_prime()
        self.q = self.generate_prime()
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = self.generate_e()
        self.d = self.generate_d()

    def generate_prime(self):
        while True:
            prime = secrets.randbits(self.bits)
            if self.is_prime(prime):
                return prime

    def is_prime(self, n):
        if n < 2:
            return False
        if n < 4:
            return True
        if n % 2 == 0:
            return False
        for i in range(3, math.isqrt(n) + 1, 2):
            if n % i == 0:
                return False
        return True

    def generate_e(self):
        e = 65537
        while math.gcd(e, self.phi) != 1:
            e += 2
        return e

    def generate_d(self):
        d = 1
        while (d * self.e) % self.phi != 1:
            d += 1
        return d

    def encrypt(self, message):
        return pow(message, self.e, self.n)

    def decrypt(self, cipher):
        return pow(cipher, self.d, self.n)
    
    def get_public_key(self):
        return self.e, self.n
    
    def get_private_key(self):
        return self.d, self.n
    
    def get_phi(self):
        return self.phi
    
    def generate_key_pair(self):
        return (self.get_public_key(), self.get_private_key())