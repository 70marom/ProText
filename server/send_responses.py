import json
from server.response import Response
from server.response_codes import ResponseCodes


class SendResponses:
    def __init__(self, conn, keys):
        self.keys = keys
        self.conn = conn
        self.response = Response(keys)

    def invalid_tel(self):
        self.response.send_response(self.conn, ResponseCodes.INVALID_PHONE, b"")

    def invalid_code(self):
        self.response.send_response(self.conn, ResponseCodes.INVALID_AUTH_CODE, b"")

    def expired_code(self):
        self.response.send_response(self.conn, ResponseCodes.EXPIRED_AUTH_CODE, b"")

    def sending_code(self):
        self.response.send_response(self.conn, ResponseCodes.TWO_FACTOR_AUTH, b"")

    def register_successful(self):
        self.response.send_response(self.conn, ResponseCodes.REGISTER_SUCCESS, b"")

    def login_successful(self):
        self.response.send_response(self.conn, ResponseCodes.LOGIN_SUCCESS, b"")

    def send_count_pending_messages(self, count_list):
        serialized_data = json.dumps(count_list)
        self.response.send_response(self.conn, ResponseCodes.PENDING_MESSAGE_COUNT, serialized_data.encode('utf-8'))

    def invalid_contact(self):
       self.response.send_response(self.conn, ResponseCodes.INVALID_CONTACT, b"")

    def send_public_key(self, public_key):
        self.response.send_response(self.conn, ResponseCodes.PUBLIC_KEY_RECEIVED, public_key)

    def send_message(self, payload, conn=None):
        if conn:
            self.response.send_response(conn, ResponseCodes.MESSAGE_RECEIVED, payload)
        else:
            self.response.send_response(self.conn, ResponseCodes.MESSAGE_RECEIVED, payload)