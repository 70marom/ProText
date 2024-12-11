import struct

class Response:
    def __init__(self, code, payload):
        self.code = code
        self.payload = payload
        self.payload_size = len(payload)

    def send_response(self, conn):
        conn.sendall(struct.pack('!I I', self.code, self.payload_size))
        conn.sendall(self.payload)