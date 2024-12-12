import os.path
import struct
import threading

from client.aes import AES
from client.console import Console
from client.keys_folders import save_files
from client.send_requests import SendRequests
from client.rsa import RSA
import json

class Session:
    def __init__(self, socket):
        self.socket = socket
        self.send_requests = SendRequests(socket, None)
        self.tel = None
        self.running = True
        self.keys = RSA()
        self.encrypted_self_aes = dict()
        self.decrypted_self_aes = dict()
        self.console = Console(self)
        self.console.start_window()

    def set_tel(self, tel):
        self.tel = tel
        self.send_requests.tel = tel

    def receive_messages(self):
        while self.running:
            try:
                header = self.socket.recv(8)
                if not header or len(header) != 8:
                    print("Error: invalid header from server!")
                    self.running = False

                code, payload_size = struct.unpack('!I I', header)
                payload = None
                if payload_size > 0:
                    payload = self.socket.recv(payload_size)

                    if not payload or len(payload) != payload_size:
                        print("Error: invalid payload from client!")
                        self.running = False

            except Exception as e:
                print(f"Session Error: {e}")
                self.running = False
                return

            match code:
                case 300:
                    print("Invalid phone number! Server could not verify phone number.")
                    self.console.start_window()
                case 400:
                    self.handle_2fa()
                case 401:
                    self.console.show_pending_count(json.loads(payload.decode()))
                    threading.Thread(target=self.console.choose_contact).start()
                case 200:
                    print("Registered successfully in the server!")
                    save_files(self.keys, self.tel)
                    threading.Thread(target=self.console.choose_contact).start()
                case 202:
                    print("Login successfully in the server!")
                case 301:
                    print("Invalid authentication code! Please try again.")
                    self.console.validate_2fa()
                case 302:
                    print("Authentication code expired! Please try again.")
                case 303:
                    print("Invalid contact! Please try again.")
                    threading.Thread(target=self.console.choose_contact).start()
                case 203:
                    self.create_encrypt_save_aes(payload)
                    threading.Thread(target=self.console.chat).start()


    def register(self):
        self.keys.generate_keys()
        self.send_requests.register_request()

    def login(self):
        self.keys.load_public_key(os.path.join(self.tel, "public_key.pem"))
        self.keys.load_private_key(os.path.join(self.tel, "private_key.pem"))
        self.send_requests.login_request()

    def handle_2fa(self):
        auth_code = self.socket.recv(6).decode()
        print(f"Received 2FA code: {auth_code}")
        self.console.validate_2fa()

    def create_encrypt_save_aes(self, rsa_key):
        aes = AES()
        rsa = RSA()

        rsa.load_public_key(key=rsa_key)
        print(rsa_key)
        print(type(rsa))
        enc_aes_iv_key = rsa.encrypt(b"G")
        print("here")
        self.encrypted_self_aes[self.console.contact] = enc_aes_iv_key
        self.decrypted_self_aes[self.console.contact] = aes
