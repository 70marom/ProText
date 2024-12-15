from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


class RSA:
    def __init__(self):
        self.public_key = None
        self.private_key = None

    def generate_keys(self, size=1024):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=size
        )
        self.public_key = self.private_key.public_key()

    def load_public_key(self, key_path="server_public_key.pem", key=None):
        if key:
            self.public_key = load_pem_public_key(
                key,
                backend=default_backend()
            )
            return
        with open(key_path, "rb") as key_file:
            self.public_key = load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

    def load_private_key(self, key_path):
        with open(key_path, "rb") as key_file:
            self.private_key = load_pem_private_key(
                key_file.read(),
                backend=default_backend(),
                password=None
            )

    def encrypt(self, data):
        if not isinstance(data, bytes):
            data = data.encode('utf-8')

        ciphertext = self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt(self, ciphertext):
        if not isinstance(ciphertext, bytes):
            ciphertext = ciphertext.encode('utf-8')

        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def get_public_pem(self):
        return self.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    def get_private_pem(self):
        return self.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )