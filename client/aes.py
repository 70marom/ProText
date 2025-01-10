import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class AES:
    KEY_SIZE = 32
    IV_SIZE = 16

    def __init__(self):
        # randomly generate AES key and IV, 256-bit key
        self.key = os.urandom(AES.KEY_SIZE)
        self.iv = os.urandom(AES.IV_SIZE)
        # create AES cipher object with key and IV
        self.cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=default_backend())
        print("New AES key and IV generated.")

    def set_aes(self, key, iv):
        self.key = key
        self.iv = iv
        # create AES cipher object with given key and IV
        self.cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=default_backend())
        print("AES key and IV set.")

    def encrypt(self, data):
        encryptor = self.cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def decrypt(self, data):
        decryptor = self.cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()
