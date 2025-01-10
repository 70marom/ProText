import random
import time

from server.response_codes import ResponseCodes


class SecureChannelAuth:
    TIME_LIMIT = 180
    def __init__(self):
        # generate a random 6-digit auth code
        self.auth_code = f"{random.randint(0, 999999):06}"
        self.time_now = time.time()

    def send_by_secure_channel(self, conn):
        conn.sendall(self.auth_code.encode())

    def verify_auth_code(self, auth_code):
        # check if the time limit is exceeded
        if time.time() - self.time_now > SecureChannelAuth.TIME_LIMIT:
            return ResponseCodes.EXPIRED_AUTH_CODE
        if auth_code == self.auth_code:
            return ResponseCodes.REGISTER_SUCCESS
        return ResponseCodes.INVALID_AUTH_CODE