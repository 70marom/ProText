import struct

class Request:
    def __init__(self, tel, keys):
        self.tel = tel
        self.keys = keys

    def send_request(self, s, code, payload):
        # header is 10 bytes of tel, 4 bytes of code, 4 bytes of payload length
        header = struct.pack('!10s I I', self.tel.encode(), code, len(payload) + 128)
        # sign the header and the payload using the RSA keys
        signature = self.keys.sign(header + payload)
        # send the header, payload and signature to the server
        s.sendall(header)
        s.sendall(payload + signature)
