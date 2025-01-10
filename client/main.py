import socket
from client.session import Session

def main():
    port = 9090
    ip = 'localhost'
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((ip, port))
            print("Connected to server!")
            # create a session object
            session = Session(s)
            # start the session
            session.receive_messages()

        except Exception as e:
            print(f"Main Error: {e}.")
            print("Error: failed to connect to server!")

if __name__ == '__main__':
    main()
