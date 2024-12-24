import json
from server.response import Response

class SendResponses:
    def __init__(self, conn, keys):
        self.keys = keys
        self.conn = conn
        self.response = Response(keys)

    def invalid_tel(self):
        self.response.send_response(self.conn, 300, b"")

    def invalid_code(self):
        self.response.send_response(self.conn, 301, b"")

    def expired_code(self):
        self.response.send_response(self.conn, 302, b"")

    def sending_code(self):
        self.response.send_response(self.conn, 400, b"")

    def register_successful(self):
        self.response.send_response(self.conn, 200, b"")

    def login_successful(self):
        self.response.send_response(self.conn, 202, b"")

    def send_count_pending_messages(self, count_list):
        serialized_data = json.dumps(count_list)
        self.response.send_response(self.conn, 401, serialized_data.encode('utf-8'))

    def invalid_contact(self):
       self.response.send_response(self.conn, 303, b"")

    def send_public_key(self, public_key):
        self.response.send_response(self.conn, 203, public_key)

    def send_message(self, payload):
        self.response.send_response(self.conn, 402, payload)