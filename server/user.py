import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from server.rsa_server import RSAServer, verify_signature
from server.secure_channel_auth import SecureChannelAuth
from server.send_responses import SendResponses
tel_sockets_dict = dict()

class User:
    def __init__(self, conn, addr, database):
        self.conn = conn
        self.addr = addr
        self.database = database
        self.tel = None
        self.running = True
        self.auth_code = None
        self.keys = RSAServer()
        self.keys.load_keys()
        self.registering = False
        self.client_public_key = None
        self.send_responses = SendResponses(conn, self.keys)

    def receive_messages(self):
        while self.running:
            try:
                header = self.conn.recv(18)
                if not header or len(header) != 18:
                    print("Error: invalid header from client!")
                    self.running = False

                tel, code, payload_size = struct.unpack('!10s I I', header)
                payload = None
                if payload_size > 0:
                    payload = self.conn.recv(payload_size)

                    if not payload or len(payload) != payload_size:
                        print("Error: invalid payload from client!")
                        self.running = False

            except Exception as e:
                print(f"Error: {e}")
                self.running = False
                return

            if self.client_public_key:
                signature = payload[-128:]
                if not verify_signature(header + payload[:-128], signature, self.client_public_key):
                    print("Error: invalid signature from client!")
                    self.running = False
                    return
                payload = payload[:-128]

            match code:
                case 100:
                    self.handle_register_request(tel)
                case 101:
                    self.handle_2fa(payload)
                case 103:
                    self.handle_login_request(tel)
                case 104:
                    self.handle_request_public_key(payload)
                case 105:
                    self.forward_message(payload)


    def handle_register_request(self, tel):
        if not isinstance(tel, str):
            tel = tel.decode()
        if self.database.tel_exists(tel):
            print(f"{self.addr} tried to register with an existing phone number!")
            self.send_responses.invalid_tel()
            return
        self.registering = True
        self.tel = tel
        self.auth_code = SecureChannelAuth()
        self.send_responses.sending_code()
        self.auth_code.send_by_secure_channel(self.conn)
        print(f"Sent auth code to {self.addr}")

    def handle_login_request(self, tel):
        if not isinstance(tel, str):
            tel = tel.decode()
        if not self.database.tel_exists(tel):
            print(f"{self.addr} tried to login with a non existing phone number!")
            self.send_responses.invalid_tel()
            return
        if tel in tel_sockets_dict:
            print(f"{self.addr} tried to login with a phone number already logged in!")
            self.send_responses.invalid_tel()
            return
        self.tel = tel
        self.auth_code = SecureChannelAuth()
        self.send_responses.sending_code()
        self.auth_code.send_by_secure_channel(self.conn)
        print(f"Sent auth code to {self.addr}")

    def handle_2fa(self, payload):
        encrypted_aes_key = payload[:128]  # 256 bytes: 256-bit AES key + 16-byte IV
        encrypted_code_and_key = payload[128:]  # Remaining part is the encrypted payload (code + public key)

        decrypted_aes_key_iv = self.keys.decrypt(encrypted_aes_key)

        aes_key = decrypted_aes_key_iv[:32]
        iv = decrypted_aes_key_iv[32:]

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        dec_payload = decryptor.update(encrypted_code_and_key) + decryptor.finalize()

        decrypted_code = dec_payload[:6]  # Assuming the code is 6 bytes
        decrypted_key = dec_payload[6:]  # The remaining part is the RSA public key

        self.client_public_key = decrypted_key

        match self.auth_code.verify_auth_code(decrypted_code.decode()):
            case 200:  # Accepted
                if self.registering:
                    self.database.add_client(self.tel, decrypted_key)
                    print(f"{self.addr} registered with phone number {self.tel}")
                    tel_sockets_dict[self.tel] = self.conn
                    self.send_responses.register_successful()
                else:
                    print(f"{self.addr} logged in with phone number {self.tel}")
                    tel_sockets_dict[self.tel] = self.conn
                    self.send_responses.login_successful()
                    self.send_responses.send_count_pending_messages(self.database.get_number_of_pending_messages(self.tel))
                    self.send_pending_messages()
            case 301:  # Invalid code
                self.send_responses.invalid_code()
                print(f"{self.addr} entered an invalid authentication code!")
            case 302:  # Expired
                self.send_responses.expired_code()
                print(f"{self.addr} entered an expired authentication code!")
                self.handle_register_request(self.tel)

    def handle_request_public_key(self, payload):
        contact = payload.decode()
        public_key = self.database.get_public_key(contact)
        if public_key is None:
            print(f"{self.addr} requested public key of non existing contact {contact}")
            self.send_responses.invalid_contact()
            return
        self.send_responses.send_public_key(public_key[0])
        print(f"Sent public key of {contact} to {self.addr}")

    def forward_message(self, payload):
        try:
            contact = payload[:10]
            if not isinstance(contact, str):
                contact = contact.decode()
            conn = tel_sockets_dict[contact]
            payload = self.tel.encode() + payload[10:]
            self.send_responses.send_message(payload, conn)

        except Exception as e:
            tel_dst, new_connection, encrypted_aes_key = struct.unpack('!10s 1s 128s', payload[:139])
            if not isinstance(tel_dst, str):
                tel_dst = tel_dst.decode()
            if not isinstance(new_connection, int):
                new_connection = int(new_connection)
            if new_connection == 1:
                new_connection = True
            else:
                new_connection = False
            msg = payload[139:]
            self.database.save_message(self.tel, tel_dst, new_connection, encrypted_aes_key, msg)

    def send_pending_messages(self):
        pending_messages = self.database.get_pending_messages(self.tel)
        self.database.delete_pending_messages(self.tel)
        for msg in pending_messages:
            tel_src, new_connection, encrypted_aes_key, encrypted_msg = msg
            payload = tel_src.encode() + str(new_connection).encode() + encrypted_aes_key + encrypted_msg
            self.send_responses.send_message(payload)