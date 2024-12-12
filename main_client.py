import socket

from client.session import Session

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect(('localhost', 9999))
            print("Connected to server!")
            session = Session(s)
            session.receive_messages()

        except Exception as e:
            print(f"Main Error: {e}")
            print("Error: failed to connect to server!")

if __name__ == '__main__':
    main()
