from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
from client.request import Request
from client.rsa import RSA


class SendRequests:
    def __init__(self, socket, tel):
        self.tel = tel
        self.socket = socket

    def register_request(self):
        Request(self.tel, 100, b"").send_request(self.socket)

    def login_request(self):
        Request(self.tel, 103, b"").send_request(self.socket)

    def try_auth(self, code, keys):
        if not isinstance(code, bytes):
            code = code.encode('utf-8')

        public_key_pem = keys.get_public_pem()

        aes_key = os.urandom(32)  # 256-bit AES key

        server_key = RSA()
        server_key.load_public_key(key_path="server_public_key.pem")

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_payload = encryptor.update(code + public_key_pem) + encryptor.finalize()

        encrypted_aes_key = server_key.encrypt(aes_key + iv)

        combined_payload = encrypted_aes_key + encrypted_payload

        Request(self.tel, 101, combined_payload).send_request(self.socket)

    def request_contact_public_key(self, contact_tel):
        Request(self.tel, 104, contact_tel.encode()).send_request(self.socket)

    def send_message(self, contact_tel, new_connection, encrypted_aes, message):
        if not isinstance(contact_tel, bytes):
            contact_tel = contact_tel.encode('utf-8')

        payload = contact_tel + f"{new_connection}".encode() + encrypted_aes + message
        Request(self.tel, 105, payload).send_request(self.socket)
