import struct

class Request:
    def __init__(self, tel, code, payload):
        self.tel = tel
        self.code = code
        self.payload = payload
        self.payload_size = len(payload)

    def send_request(self, s):
        s.sendall(struct.pack('!10s I I', self.tel.encode(), self.code, self.payload_size))
        s.sendall(self.payload)
