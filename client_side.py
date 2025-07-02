import socket
import ssl
import os

HOST = "127.0.0.1"  # server ip
PORT = 8080  # server port
DEFAULT_PATH = r"C:\Users\d9787\Desktop\Cyber\recovered_files"  # where save files


class PersistentClient:
    def __init__(self, username, host=HOST, port=PORT, path=DEFAULT_PATH):
        self.host = host
        self.port = port
        self.path = path
        self.socket = None
        self.connected = False

        self.username = username.strip()[:10]
        self.username_encoded = self.username.encode()
        self.username_len = len(self.username_encoded)

    def connect(self):
        if self.connected:
            return

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket = context.wrap_socket(raw_sock, server_hostname=self.host)
            self.socket.connect((self.host, self.port))
            self.connected = True
            print(f"[+] Connected to server as '{self.username}'")
        except Exception as e:
            print(f"[!] Could not connect to server: {e}")
            self.connected = False

    def send_files(self, file_list):
        if not self.connected:
            raise ConnectionError("Not connected to server.")

        for filename in file_list:
            full_path = os.path.join(self.path, filename)
            if not os.path.isfile(full_path):
                continue

            with open(full_path, "rb") as f:
                file_data = f.read()

            filename_encoded = filename.encode()
            self.socket.send(f"{self.username_len:01}".encode())
            self.socket.send(self.username_encoded)

            self.socket.send(f"{len(filename_encoded):02}".encode())
            self.socket.send(filename_encoded)

            self.socket.send(f"{len(file_data):08}".encode())
            self.socket.sendall(file_data)

            ack = self.socket.recv(2)
            if ack != b"OK":
                raise Exception(f"Server did not acknowledge {filename}")

    def pause(self):
        if self.connected and self.socket:
            try:
                self.socket.send(b"00")
            except:
                pass

    def close(self):
        if self.connected and self.socket:
            try:
                self.socket.send(b"00")
            except:
                pass
            self.socket.close()
            print("[+] Connection closed.")
        self.connected = False
