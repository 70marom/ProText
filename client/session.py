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
        self.tel = None
        self.running = True
        self.keys = RSA()
        self.server_key = RSA()
        self.server_key.load_public_key(key_path="server_public_key.pem")
        self.send_requests = SendRequests(socket, None, self.keys)
        self.encrypted_self_aes = dict()
        self.decrypted_self_aes = dict()
        self.decrypted_contact_aes = dict()
        self.console = Console(self)
        self.console.start_window()

    def set_tel(self, tel):
        self.tel = tel
        self.send_requests.request.tel = tel

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
                        print("Error: invalid payload from server!")
                        self.running = False

            except Exception as e:
                print(f"Session Error: {e}")
                self.running = False
                return

            signature = payload[-128:]
            if not self.server_key.verify_signature(header + payload[:-128], signature):
                print("Error: invalid signature from server!")
                self.running = False
                return
            payload = payload[:-128]

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
                case 402:
                    decrypted_messages, tel_src = self.decrypt_aes_message(payload)
                    self.console.save_or_display(decrypted_messages, tel_src)


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
        enc_aes_iv_key = rsa.encrypt(aes.key + aes.iv)
        self.encrypted_self_aes[self.console.contact] = enc_aes_iv_key
        self.decrypted_self_aes[self.console.contact] = aes

    def decrypt_aes_message(self, payload):
        tel_src, new_connection, encrypted_aes_key = struct.unpack('!10s 1s 128s', payload[:139])
        encrypted_message = payload[139:]
        if new_connection.decode() == '1' or tel_src.decode() not in self.decrypted_contact_aes:
            zipped = self.keys.decrypt(encrypted_aes_key)
            (aes_key, iv) = zipped[:32], zipped[32:48]
            aes = AES()
            aes.set_aes(aes_key, iv)
            self.decrypted_contact_aes[tel_src.decode()] = aes
        decrypted_message = self.decrypted_contact_aes[tel_src.decode()].decrypt(encrypted_message)
        return decrypted_message.decode(), tel_src.decode()



