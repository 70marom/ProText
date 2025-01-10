import socket
import threading
from server.database import Database
from server.user import User, tel_sockets_dict


def session(conn, addr, database):
    print(f"New connection from {addr}")
    # create a new user object to handle the connection
    user = User(conn, addr, database)
    # start to receive messages from the user
    user.receive_messages()
    print(f"Disconnected from {addr}")
    # remove the user from the tel_sockets_dict
    tel_sockets_dict.pop(user.tel, None)
    conn.close()

def main():
    port = 9090
    ip = 'localhost'
    database = Database()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((ip, port))
            s.listen()
            print(f"Server is listening on port {port}")
            while True:
                conn, addr = s.accept()
                # create a new thread to handle the new connection
                client_thread = threading.Thread(target=session, args=(conn, addr, database))
                client_thread.start()
        except Exception as e:
            print(f"Error: failed to start server!\n{e}")

if __name__ == '__main__':
    main()