from cryptography import exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key

class RSAServer:
    def __init__(self):
        self.public_key = None
        self.private_key = None

    def load_keys(self, key_path="server_public_key.pem", private_key_path="server_private_key.pem"):
        with open(key_path, "rb") as key_file:
            self.public_key = load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        with open(private_key_path, "rb") as key_file:
            self.private_key = load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
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
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def sign(self, message):
        return self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify_signature(self, message, signature):
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except exceptions.InvalidSignature:
            return False


def verify_signature(message, signature, public_key):
    try:
        # load public key from PEM format
        public_key = load_pem_public_key(
            public_key,
            backend=default_backend()
        )
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except exceptions.InvalidSignature:
        return False