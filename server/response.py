import struct

class Response:
    def __init__(self, keys):
        self.keys = keys

    def send_response(self, conn, code, payload):
        header = struct.pack('!I I', code, len(payload) + 128)
        signature = self.keys.sign(header + payload)
        conn.sendall(header)
        conn.sendall(payload + signature)