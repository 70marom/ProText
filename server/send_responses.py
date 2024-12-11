import json
from server.response import Response

def invalid_tel(conn):
    Response(300, b"").send_response(conn)

def invalid_code(conn):
    Response(301, b"").send_response(conn)

def expired_code(conn):
    Response(302, b"").send_response(conn)

def sending_code(conn):
    Response(400, b"").send_response(conn)

def register_successful(conn):
    Response(200, b"").send_response(conn)

def login_successful(conn):
    Response(202, b"").send_response(conn)

def send_count_pending_messages(conn, count_list):
    serialized_data = json.dumps(count_list)
    Response(401, serialized_data.encode('utf-8')).send_response(conn)

def invalid_contact(conn):
    Response(303, b"").send_response(conn)

def send_public_key(conn, public_key):
    Response(203, public_key).send_response(conn)