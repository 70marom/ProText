import re

class Console:
    def __init__(self, session):
        self.session = session
        self.contact = None
        self.new_connection = True
        self.session.console = self
        self.pending_messages = dict()
        print("Welcome to the ProText secure messaging system!")


    def start_window(self):
        while True:
            tel = input("Enter phone number: ")
            if len(tel) != 10 or re.match(r"^05\d{8}$", tel) is None:
                print("Invalid phone number! Please enter a 10-digit phone number That start with 05")
                continue

            self.session.set_tel(tel)
            print("What would you like to do?")
            print("1. Login")
            print("2. Register")
            choice = input("Enter your choice: ")
            if choice == "1":
                self.session.login()
                break
            elif choice == "2":
                self.session.register()
                break
            else:
                print("Invalid choice")

    def validate_2fa(self):
        while True:
            user_code = input("Enter your authentication code: ")
            if re.match(r"^\d{6}$", user_code) is None:
                print("Invalid authentication code! Please enter a 6-digit code")
                continue
            break
        print("Sending authentication code to server...")
        self.session.send_requests.try_auth(user_code, self.session.keys)

    def choose_contact(self):
        while True:
            contact = input("Choose a contact: ")
            if contact == self.session.tel:
                print("You cannot send messages to yourself!")
                continue
            else:
                break
        self.contact = contact
        self.new_connection = 1
        self.session.send_requests.request_contact_public_key(contact)

    def show_pending_count(self, count_list):
        if len(count_list) == 0:
            print("No pending messages.")
            return
        print("Pending messages:")
        for tup in count_list:
            if tup[1] > 0:
                print(f"\tFrom {tup[0]}: {tup[1]} messages")

    def chat(self):
        print("Chatting with ", self.contact)
        print("Type '\\home' to exit the chat")
        if self.contact in self.pending_messages:
            for msg in self.pending_messages[self.contact]:
                print(f"Partner: {msg}")
            self.pending_messages[self.contact] = []
        while True:
            message = input("Enter message: ")
            if message == "\\home":
                self.contact = None
                return self.choose_contact()
            encrypted_message = self.session.decrypted_self_aes[self.contact].encrypt(message.encode())
            self.session.send_requests.send_message(self.contact, self.new_connection, self.session.encrypted_self_aes[self.contact], encrypted_message)
            self.new_connection = 0


    def save_or_display(self, decrypted_messages, tel_src):
        if tel_src not in self.pending_messages:
            self.pending_messages[tel_src] = []
        if tel_src != self.contact:
            self.pending_messages[tel_src].append(decrypted_messages)
        else:
            print(f"Partner: {decrypted_messages}")
