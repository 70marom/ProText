import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class AES:
    def __init__(self):
        self.key = os.urandom(32)
        self.iv = os.urandom(16)
        self.cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=default_backend())
        print("New AES key and IV generated.")

    def set_aes(self, key, iv):
        self.key = key
        self.iv = iv
        self.cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=default_backend())
        print("AES key and IV set.")

    def encrypt(self, data):
        encryptor = self.cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def decrypt(self, data):
        decryptor = self.cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()
