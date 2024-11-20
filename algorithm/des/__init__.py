from .decryption import decryption
from .encryption import encryption
from .helper import str_to_bin

class DES:
    def __init__(self, key):
        self.key = key
        

    def encrypt(self, plaintext):
        enc = encryption(plaintext)
        return enc

    def decrypt(self, ciphertext):
        enc_to_binary = str_to_bin(ciphertext)
        return decryption(enc_to_binary)