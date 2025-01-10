import struct

class Response:
    def __init__(self, keys):
        self.keys = keys

    def send_response(self, conn, code, payload):
        # header is 8 bytes long, 4 bytes for code and 4 bytes for payload length
        header = struct.pack('!I I', code, len(payload) + 128)
        # sign the header and payload
        signature = self.keys.sign(header + payload)
        # send the header, payload and signature
        conn.sendall(header)
        conn.sendall(payload + signature)