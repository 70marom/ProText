import sqlite3
import threading

class Database:
    def __init__(self):
        self.connection = sqlite3.connect('database.db', check_same_thread=False)
        self.cursor = self.connection.cursor()
        self.lock = threading.Lock()
        self.create_clients_table()
        self.create_messages_table()

    def create_clients_table(self):
        with self.lock:
            self.cursor.execute("CREATE TABLE IF NOT EXISTS " +
                                "clients (Tel CHAR(10) PRIMARY KEY, " +
                                "PublicKey BINARY(272))")
            self.connection.commit()

    def create_messages_table(self):
        with self.lock:
            self.cursor.execute("CREATE TABLE IF NOT EXISTS " +
                                "messages (TelSrc CHAR(10), TelDst CHAR(10)," +
                                "NewConnection BOOL, EncAES BINARY(128), " +
                                "EncMsg VARBINARY(65535), " +
                                "ID INT AUTO_INCREMENT PRIMARY KEY)") # Auto increments the MsgID on every entry
            self.connection.commit()

    def tel_exists(self, tel):
        with self.lock:
            self.cursor.execute("SELECT * FROM clients WHERE Tel = ?", (tel,))
            return self.cursor.fetchone() is not None

    def add_client(self, tel, public_key):
        with self.lock:
            self.cursor.execute("INSERT INTO clients (Tel, PublicKey) VALUES (?, ?)", (tel,public_key))
            self.connection.commit()

    def get_number_of_pending_messages(self, tel):
        with self.lock:
            # return a list of tuples where each tuple is a source tel for the parameter tel, and the second is the amount of messages from this source
            self.cursor.execute("SELECT TelSrc, COUNT(*) FROM messages WHERE TelDst = ? GROUP BY TelSrc", (tel,))
            return self.cursor.fetchall()

    def get_public_key(self, tel):
        with self.lock:
            self.cursor.execute("SELECT PublicKey FROM clients WHERE Tel = ?", (tel,))
            return self.cursor.fetchone()