import struct

class Request:
    def __init__(self, tel, keys):
        self.tel = tel
        self.keys = keys

    def send_request(self, s, code, payload):
        header = struct.pack('!10s I I', self.tel.encode(), code, len(payload) + 128)
        signature = self.keys.sign(header + payload)
        s.sendall(header)
        s.sendall(payload + signature)
