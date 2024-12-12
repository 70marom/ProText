import socket
import threading
from server.database import Database
from server.user import User

def session(conn, addr, database):
    print(f"New connection from {addr}")
    user = User(conn, addr, database)
    user.receive_messages()
    print(f"Disconnected from {addr}")
    conn.close()

def main():
    database = Database()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('localhost', 9999))
            s.listen()
            print("Server is listening on port 9999")
            while True:
                conn, addr = s.accept()
                client_thread = threading.Thread(target=session, args=(conn, addr, database))
                client_thread.start()
        except Exception as e:
            print(f"Error: failed to start server!\n{e}")

if __name__ == '__main__':
    main()