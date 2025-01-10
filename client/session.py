import os.path
import struct
import threading
from client.aes import AES
from client.console import Console
from client.keys_folders import save_files
from client.response_codes import ResponseCodes
from client.send_requests import SendRequests
from client.rsa import RSA
import json

class Session:
    def __init__(self, socket):
        self.socket = socket
        self.tel = None
        self.running = True
        self.keys = RSA() # client keys
        self.server_key = RSA() # server's public key
        self.server_key.load_public_key(key_path="server_public_key.pem")
        self.send_requests = SendRequests(socket, None, self.keys)
        self.encrypted_self_aes = dict() # encrypted aes keys for each contact
        self.decrypted_self_aes = dict() # decrypted aes keys for each contact
        self.decrypted_contact_aes = dict() # decrypted aes keys for messages coming from contacts
        self.console = Console(self)
        self.console.start_window()

    def set_tel(self, tel):
        self.tel = tel
        self.send_requests.request.tel = tel

    def receive_messages(self):
        header_size = 8
        signature_size = 128
        while self.running:
            try:
                header = self.socket.recv(header_size)
                if not header or len(header) != header_size:
                    print("Error: invalid header from server!")
                    self.running = False
                # header from server is code and payload size
                code, payload_size = struct.unpack('!I I', header)
                payload = None
                if payload_size > 0:
                    payload = self.socket.recv(payload_size)

                    if not payload or len(payload) != payload_size:
                        print("Error: invalid payload from server!")
                        self.running = False

            except Exception as e:
                if(self.running):
                    print(f"Session Error: {e}")
                self.running = False
                return
            # signature is the last 128 bytes of the payload
            signature = payload[-signature_size:]
            # verify signature with server's public key
            if not self.server_key.verify_signature(header + payload[:-signature_size], signature):
                print("Error: invalid signature from server!")
                self.running = False
                return
            # remove signature from payload
            payload = payload[:-signature_size]

            match code:
                case ResponseCodes.INVALID_PHONE:
                    print("Invalid phone number! Server could not verify phone number.")
                    self.console.start_window()
                case ResponseCodes.TWO_FACTOR_AUTH:
                    self.handle_2fa()
                case ResponseCodes.PENDING_MESSAGE_COUNT:
                    self.console.show_pending_count(json.loads(payload.decode()))
                    threading.Thread(target=self.console.choose_contact).start()
                case ResponseCodes.REGISTER_SUCCESS:
                    print("Registered successfully in the server!")
                    save_files(self.keys, self.tel)
                    threading.Thread(target=self.console.choose_contact).start()
                case ResponseCodes.LOGIN_SUCCESS:
                    print("Login successfully in the server!")
                case ResponseCodes.INVALID_AUTH_CODE:
                    print("Invalid authentication code! Please try again.")
                    self.console.validate_2fa()
                case ResponseCodes.EXPIRED_AUTH_CODE:
                    print("Authentication code expired! Please try again.")
                case ResponseCodes.INVALID_CONTACT:
                    print("Invalid contact! Please try again.")
                    threading.Thread(target=self.console.choose_contact).start()
                case ResponseCodes.PUBLIC_KEY_RECEIVED:
                    self.create_encrypt_save_aes(payload)
                    threading.Thread(target=self.console.chat).start()
                case ResponseCodes.MESSAGE_RECEIVED:
                    decrypted_messages, tel_src = self.decrypt_aes_message(payload)
                    self.console.save_or_display(decrypted_messages, tel_src)


    def register(self):
        # generate keys and register request
        self.keys.generate_keys()
        self.send_requests.register_request()

    def login(self):
        # load keys and login request
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
        # save encrypted and decrypted aes keys for contact
        self.encrypted_self_aes[self.console.contact] = enc_aes_iv_key
        self.decrypted_self_aes[self.console.contact] = aes

    def decrypt_aes_message(self, payload):
        # payload is tel_src, new_connection, encrypted_aes_key, encrypted_message
        tel_src, new_connection, encrypted_aes_key = struct.unpack('!10s 1s 128s', payload[:139])
        encrypted_message = payload[139:]
        # if new_connection is 1 or tel_src is not in decrypted_contact_aes, decrypt aes key
        if new_connection.decode() == '1' or tel_src.decode() not in self.decrypted_contact_aes:
            zipped = self.keys.decrypt(encrypted_aes_key)
            (aes_key, iv) = zipped[:32], zipped[32:48]
            aes = AES()
            aes.set_aes(aes_key, iv)
            self.decrypted_contact_aes[tel_src.decode()] = aes
        decrypted_message = self.decrypted_contact_aes[tel_src.decode()].decrypt(encrypted_message)
        return decrypted_message.decode(), tel_src.decode()
