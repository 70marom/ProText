import random
import time


class SecureChannelAuth:
    TIME_LIMIT = 180
    def __init__(self):
        self.auth_code = f"{random.randint(0, 999999):06}"
        self.time_now = time.time()

    def send_by_secure_channel(self, conn):
        conn.sendall(self.auth_code.encode())

    def verify_auth_code(self, auth_code):
        if time.time() - self.time_now > SecureChannelAuth.TIME_LIMIT:
            return 302
        if auth_code == self.auth_code:
            return 200
        return 301