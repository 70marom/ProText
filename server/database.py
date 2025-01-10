import sqlite3
import threading

class Database:
    def __init__(self):
        self.connection = sqlite3.connect('database.db', check_same_thread=False)
        self.cursor = self.connection.cursor()
        self.lock = threading.Lock() # lock to prevent multiple threads from accessing the database at the same time
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
            return self.cursor.fetchone() is not None # returns True if the tel exists in the database

    def add_client(self, tel, public_key):
        with self.lock:
            self.cursor.execute("INSERT INTO clients (Tel, PublicKey) VALUES (?, ?)", (tel,public_key))
            self.connection.commit()

    def get_number_of_pending_messages(self, tel):
        with self.lock:
            # return a list of tuples where each tuple is a source tel for the parameter tel, and the second is the amount of messages from this source
            self.cursor.execute("SELECT TelSrc, COUNT(*) FROM messages WHERE TelDst = ? GROUP BY TelSrc", (tel,))
            return self.cursor.fetchall()

    def get_pending_messages(self, tel_dst):
        with self.lock:
            # return a list of tuples where each tuple is a source tel, new connection status, AES key, and encrypted message
            self.cursor.execute("SELECT TelSrc, NewConnection, EncAES, EncMsg FROM messages WHERE TelDst = ?", (tel_dst,))
            return self.cursor.fetchall()

    def delete_pending_messages(self, tel_dst):
        with self.lock:
            # delete all messages where the destination is the parameter tel
            self.cursor.execute("DELETE FROM messages WHERE TelDst = ?", (tel_dst,))
            self.connection.commit()

    def get_public_key(self, tel):
        with self.lock:
            self.cursor.execute("SELECT PublicKey FROM clients WHERE Tel = ?", (tel,))
            return self.cursor.fetchone()

    def save_message(self, tel_src, tel_dst, new_connection, enc_aes, enc_msg):
        with self.lock:
            self.cursor.execute("INSERT INTO messages " +
                                "(TelSrc, TelDst, NewConnection, EncAES, EncMsg) VALUES (?,?,?,?,?)",
                                (tel_src, tel_dst, new_connection, enc_aes, enc_msg))
            self.connection.commit()