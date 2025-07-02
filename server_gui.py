import socket
import ssl
import threading
import os
import customtkinter as ctk
import logging
import sqlite3
import hashlib
import json
import random
from email.message import EmailMessage
import smtplib
from concurrent.futures import ThreadPoolExecutor

HOST_AUTH = "127.0.0.1"  # server ip
PORT_AUTH = 9090
HOST_FILE = "127.0.0.1"  # server ip
PORT_FILE = 8080
BASE_DIR = r"C:\Users\d9787\Desktop\Cyber\server"  # server folder path

EMAIL_ADDRESS = "filerecovery6@gmail.com"
EMAIL_PASSWORD = "bimi rlyc koxv znog"

executor = ThreadPoolExecutor(max_workers=10)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

logging.basicConfig(
    filename="server_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class DatabaseManager:

    def __init__(self, db_path="data.db"):
        self.db_path = db_path
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.sql = self.db.cursor()
        self._create_tables()

    def _create_tables(self):
        self.sql.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            email TEXT,
            reset_code TEXT,
            reset_attempts INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        self.db.commit()

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def register_user(self, username, password, email):
        try:
            if self.user_exists(username):
                return {"status": "error", "message": "User already exists"}

            hashed_password = self.hash_password(password)
            self.sql.execute(
                "INSERT INTO users (username, password, email, reset_code, reset_attempts) VALUES (?, ?, ?, NULL, 0)",
                (username, hashed_password, email)
            )
            self.db.commit()
            return {"status": "ok", "message": "Registration successful"}
        except Exception as e:
            return {"status": "error", "message": f"Registration failed: {str(e)}"}

    def authenticate_user(self, username, password):
        try:
            hashed_password = self.hash_password(password)
            self.sql.execute("SELECT 1 FROM users WHERE username = ? AND password = ?", (username, hashed_password))
            if self.sql.fetchone():
                return {"status": "ok", "message": f"Welcome, {username}"}
            else:
                return {"status": "error", "message": "Invalid username or password"}
        except Exception as e:
            return {"status": "error", "message": f"Authentication failed: {str(e)}"}

    def user_exists(self, username):
        self.sql.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        return self.sql.fetchone() is not None

    def get_user_by_credentials(self, username, email):
        self.sql.execute("SELECT username FROM users WHERE username=? AND email=?", (username, email))
        return self.sql.fetchone()

    def set_reset_code(self, username, code):
        self.sql.execute("UPDATE users SET reset_code=?, reset_attempts=3 WHERE username=?", (code, username))
        self.db.commit()

    def verify_reset_code(self, username, code):
        self.sql.execute("SELECT reset_code, reset_attempts FROM users WHERE username=?", (username,))
        row = self.sql.fetchone()
        if not row:
            return {"status": "error", "message": "User not found"}

        saved_code, attempts = row
        if attempts <= 0:
            return {"status": "error", "message": "Too many failed attempts"}

        if code == saved_code:
            return {"status": "ok", "message": "Code correct"}

        self.sql.execute("UPDATE users SET reset_attempts=? WHERE username=?", (attempts - 1, username))
        self.db.commit()
        return {"status": "error", "message": "Incorrect code"}

    def reset_password(self, username, new_password):
        hashed_password = self.hash_password(new_password)
        self.sql.execute("UPDATE users SET password=?, reset_code=NULL, reset_attempts=0 WHERE username=?",
                         (hashed_password, username))
        self.db.commit()
        return {"status": "ok", "message": "Password updated"}

    def get_user_count(self):
        self.sql.execute("SELECT COUNT(*) FROM users")
        return self.sql.fetchone()[0]

    def close(self):
        self.db.close()


db_manager = DatabaseManager()


def send_reset_email(to_email, code):
    msg = EmailMessage()
    msg["Subject"] = "Password Reset Code"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    msg.set_content(f"Your reset code is: {code}")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)


def handle_auth_request(data):
    action = data.get("action")
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if action == "register":
        email = data.get("email", "").strip()
        if not username or not password or not email:
            return {"status": "error", "message": "Missing username, password or email"}
        return db_manager.register_user(username, password, email)

    elif action == "login":
        return db_manager.authenticate_user(username, password)

    elif action == "forgot_password":
        email = data.get("email", "").strip()
        if db_manager.get_user_by_credentials(username, email):
            code = str(random.randint(100000, 999999))
            db_manager.set_reset_code(username, code)
            send_reset_email(email, code)
            return {"status": "ok", "message": "Reset code sent to email."}
        return {"status": "error", "message": "Invalid username or email"}

    elif action == "verify_code":
        code = data.get("code", "").strip()
        return db_manager.verify_reset_code(username, code)

    elif action == "reset_password":
        new_password = data.get("new_password", "").strip()
        return db_manager.reset_password(username, new_password)

    return {"status": "error", "message": "Unknown action"}


def start_auth_server():
    def thread_target():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="server.pem", keyfile="server.key")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((HOST_AUTH, PORT_AUTH))
            sock.listen()
            print(f"[AUTH] TLS Auth Server running on {HOST_AUTH}:{PORT_AUTH}")

            with context.wrap_socket(sock, server_side=True) as ssock:
                while True:
                    conn, addr = ssock.accept()
                    with conn:
                        try:
                            data = conn.recv(1024).decode()
                            if not data:
                                continue
                            request = json.loads(data)
                            response = handle_auth_request(request)
                        except Exception as e:
                            response = {"status": "error", "message": str(e)}
                        conn.send(json.dumps(response).encode())

    threading.Thread(target=thread_target, daemon=True).start()


class ServerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("📡 Server File Viewer + Auth")
        self.geometry("800x600")

        self.info_frame = ctk.CTkFrame(self)
        self.info_frame.pack(fill="x", padx=10, pady=5)

        self.user_count_label = ctk.CTkLabel(self.info_frame, text=f"👥 Users: {db_manager.get_user_count()}")
        self.user_count_label.pack(side="left", padx=10, pady=5)

        self.client_listbox = ctk.CTkScrollableFrame(self, width=200)
        self.client_listbox.pack(side="left", fill="y", padx=10, pady=10)

        self.file_listbox = ctk.CTkScrollableFrame(self, width=580)
        self.file_listbox.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        self.server_thread = threading.Thread(target=self.start_file_server, daemon=True)
        self.server_thread.start()

        start_auth_server()

        self.refresh_clients()

    def refresh_clients(self):
        for widget in self.client_listbox.winfo_children():
            widget.destroy()

        if not os.path.isdir(BASE_DIR):
            os.makedirs(BASE_DIR)

        for client_id in os.listdir(BASE_DIR):
            path = os.path.join(BASE_DIR, client_id)
            if os.path.isdir(path):
                btn = ctk.CTkButton(self.client_listbox, text=f"📁 {client_id}",
                                    command=lambda p=path: self.load_client_files(p))
                btn.pack(fill="x", pady=5)

        self.user_count_label.configure(text=f"👥 Users: {db_manager.get_user_count()}")

        self.after(5000, self.refresh_clients)

    def load_client_files(self, path):
        for widget in self.file_listbox.winfo_children():
            widget.destroy()

        files = os.listdir(path)
        if not files:
            ctk.CTkLabel(self.file_listbox, text="(empty)", font=ctk.CTkFont(size=14)).pack(pady=10)
            return

        for file in files:
            full_path = os.path.join(path, file)
            label = ctk.CTkLabel(self.file_listbox, text=f"📄 {file}" if os.path.isfile(full_path) else f"📁 {file}",
                                 anchor="w")
            label.pack(fill="x", padx=10, pady=2)

    def start_file_server(self):
        def handle_client(conn, addr):
            print(f"[+] Connected from {addr}")
            try:
                while True:
                    name_len_raw = conn.recv(1)
                    if not name_len_raw:
                        break

                    name_len = int(name_len_raw.decode())
                    client_name = conn.recv(name_len).decode()

                    filename_len_raw = conn.recv(2)
                    if not filename_len_raw:
                        break

                    filename_len = int(filename_len_raw.decode())
                    if filename_len == 0:
                        print(f"[~] Client '{client_name}' paused.")
                        continue

                    filename = conn.recv(filename_len).decode()
                    file_length = int(conn.recv(8).decode())

                    received = b""
                    while len(received) < file_length:
                        chunk = conn.recv(min(4096, file_length - len(received)))
                        if not chunk:
                            break
                        received += chunk

                    client_dir = os.path.join(BASE_DIR, client_name)
                    os.makedirs(client_dir, exist_ok=True)

                    file_path = os.path.join(client_dir, filename)

                    if len(received) != file_length:
                        print(f"[!] Incomplete file from '{client_name}': {filename}")
                        logging.warning(f"Incomplete: {filename} from {client_name}")
                        conn.send(b"ER")
                        continue

                    try:
                        with open(file_path, "wb") as f:
                            f.write(received)
                        print(f"[+] Saved '{filename}' from '{client_name}'")
                        logging.info(f"File '{filename}' from '{client_name}' saved to '{file_path}'")
                        conn.send(b"OK")
                    except Exception as e:
                        print(f"[!] Failed to save '{filename}' from '{client_name}': {e}")
                        logging.error(f"Write error: {e}")
                        conn.send(b"ER")

            except Exception as e:
                print(f"[!] Client {addr} error: {e}")
                logging.error(f"Client error from {addr}: {e}")

            finally:
                conn.close()
                print(f"[✓] Connection with {addr} closed")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="server.pem", keyfile="server.key")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((HOST_FILE, PORT_FILE))
        s.listen()

        with context.wrap_socket(s, server_side=True) as ssock:
            print(f"[FILE] Server listening on {HOST_FILE}:{PORT_FILE}")
            while True:
                conn, addr = ssock.accept()
                executor.submit(handle_client, conn, addr)


if __name__ == "__main__":
    try:
        app = ServerApp()
        app.mainloop()
    finally:
        db_manager.close()
