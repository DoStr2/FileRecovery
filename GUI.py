import customtkinter as ctk
import threading
import os
import multiprocessing
import queue
import random
import file_recover
import client_side
import socket
import json
import ssl

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

FILE_ICONS = {
    ".txt": "📄",
    ".jpg": "🖼️",
    ".jpeg": "🖼️",
    ".png": "🖼️",
    ".zip": "🗜️",
    ".mp4": "🎬",
    ".pdf": "📕",
    ".docx": "📝",
    ".exe": "💾",
    ".py": "🐍"
}


def send_request(action, username, password, extra=None):
    HOST = '127.0.0.1'
    PORT = 9090
    request = {"action": action, "username": username, "password": password}
    if extra:
        request.update(extra)

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as ssock:
            ssock.send(json.dumps(request).encode())
            response = json.loads(ssock.recv(1024).decode())
            return response


def get_file_icon(filename):
    _, ext = os.path.splitext(filename)
    return FILE_ICONS.get(ext.lower(), "📁")


def run_recovery_process(q):
    file_recover.run()
    q.put("done")


def show_custom_popup(title="Done", message="Operation completed successfully!"):
    popup = ctk.CTkToplevel()
    popup.title(title)
    popup.geometry("300x160")
    popup.resizable(False, False)
    popup.grab_set()

    label = ctk.CTkLabel(popup, text=message, font=ctk.CTkFont(size=16, weight="bold"), wraplength=260)
    label.pack(pady=30)

    ok_button = ctk.CTkButton(popup, text="✅ OK", command=popup.destroy, width=100)
    ok_button.pack(pady=10)

    popup.update_idletasks()
    x = (popup.winfo_screenwidth() - popup.winfo_reqwidth()) // 2
    y = (popup.winfo_screenheight() - popup.winfo_reqheight()) // 2
    popup.geometry(f"+{x}+{y}")


class FileRecoveryApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🧩 File Recovery and Sending")
        self.geometry("700x700")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.client = None
        self.logged_in_user = None

        # AUTHENTICATION UI
        self.auth_frame = ctk.CTkFrame(self, width=500, height=300, corner_radius=15)
        self.auth_frame.place(relx=0.5, rely=0.5, anchor="center")

        auth_label = ctk.CTkLabel(self.auth_frame, text="🔐 Login / Register", font=ctk.CTkFont(size=22, weight="bold"))
        auth_label.grid(row=0, column=0, columnspan=2, pady=(20, 10))

        self.username_entry = ctk.CTkEntry(self.auth_frame, placeholder_text="Username", width=220)
        self.username_entry.grid(row=1, column=0, columnspan=2, pady=5)

        self.password_entry = ctk.CTkEntry(self.auth_frame, placeholder_text="Password", show="*", width=220)
        self.password_entry.grid(row=2, column=0, columnspan=2, pady=5)

        self.login_button = ctk.CTkButton(self.auth_frame, text="🔓 Login", command=self.login, width=100)
        self.login_button.grid(row=3, column=0, pady=(15, 5), padx=10)

        self.register_button = ctk.CTkButton(self.auth_frame, text="📝 Register", command=self.register, width=100)
        self.register_button.grid(row=3, column=1, pady=(15, 5), padx=10)

        self.forgot_button = ctk.CTkButton(self.auth_frame, text="Forgot Password?", command=self.forgot_password, fg_color="transparent", text_color="gray")
        self.forgot_button.grid(row=4, column=0, columnspan=2, pady=(5, 15))

        # Main interface elements (initially hidden)
        self.name_entry = None
        self.label = ctk.CTkLabel(self, text="📂 Recovered Files", font=ctk.CTkFont(size=20, weight="bold"))
        self.scroll_frame = ctk.CTkScrollableFrame(self, width=650, height=300)
        self.status_label = ctk.CTkLabel(self, text="Waiting for action...", font=ctk.CTkFont(size=14, weight="bold"))
        self.progress = ctk.CTkProgressBar(self, width=400)
        self.progress.set(0)
        self.recover_button = ctk.CTkButton(self, text="🔍 Recover Files", command=self.recover_files, width=200)
        self.send_button = ctk.CTkButton(self, text="📤 Send Selected", command=self.send_files, width=200)

        self.file_cards = []
        self.recover_queue = multiprocessing.Queue()
        self.check_recover_process_id = None
        self.recover_progress_value = 0
        self.recover_progress_updater_id = None

        self.disable_main_interface()

    def disable_main_interface(self):
        for widget in [self.label, self.scroll_frame, self.status_label,
                       self.progress, self.recover_button, self.send_button]:
            widget.pack_forget()

    def enable_main_interface(self):
        self.auth_frame.place_forget()

        self.forgot_button.configure(state="disabled")
        self.login_button.configure(state="disabled")
        self.register_button.configure(state="disabled")
        self.username_entry.configure(state="disabled")
        self.password_entry.configure(state="disabled")

        self.name_entry = ctk.CTkEntry(self, width=300, justify="center")
        self.name_entry.insert(0, self.logged_in_user)
        self.name_entry.configure(state="disabled")
        self.name_entry.pack(pady=10)

        self.label.pack(pady=10)
        self.scroll_frame.pack(pady=10)
        self.status_label.pack()
        self.progress.pack(pady=5)
        self.recover_button.pack(pady=10)
        self.send_button.pack(pady=5)

    def login(self):
        self.authenticate("login")

    def register(self):
        email = self.simple_prompt("Email", "Enter your email:")
        if not email:
            show_custom_popup("Error", "Email is required for registration.")
            return
        self.authenticate("register", {"email": email})

    def authenticate(self, mode, extra_data=None):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            show_custom_popup("Error", "Username and password are required.")
            return
        try:
            res = send_request(mode, username, password, extra_data)
            if res["status"] == "ok":
                show_custom_popup("Success", res["message"])
                self.logged_in_user = username
                self.enable_main_interface()
            else:
                show_custom_popup("Error", res["message"])
        except Exception as e:
            show_custom_popup("Error", f"Connection failed: {e}")

    def forgot_password(self):
        username = self.username_entry.get().strip()
        email = self.simple_prompt("Enter Email", "Enter your registered email:")
        if not username or not email:
            show_custom_popup("Error", "Username and email are required.")
            return

        try:
            res = send_request("forgot_password", username, "", extra={"email": email})
            if res["status"] != "ok":
                show_custom_popup("Error", res["message"])
                return

            for _ in range(3):
                code = self.simple_prompt("Enter Code", "Enter the 6-digit code sent to your email:")
                verify_res = send_request("verify_code", username, "", extra={"code": code})
                if verify_res["status"] == "ok":
                    new_pass = self.simple_prompt("New Password", "Enter new password:")
                    confirm = self.simple_prompt("Confirm Password", "Confirm new password:")
                    if new_pass == confirm:
                        reset_res = send_request("reset_password", username, "", extra={"new_password": new_pass})
                        show_custom_popup("Success", reset_res["message"])
                    else:
                        show_custom_popup("Error", "Passwords do not match.")
                    return
                else:
                    show_custom_popup("Error", verify_res["message"])

            show_custom_popup("Failed", "Too many incorrect attempts.")

        except Exception as e:
            show_custom_popup("Error", str(e))

    def simple_prompt(self, title, message):
        dialog = ctk.CTkToplevel(self)
        dialog.title(title)
        dialog.geometry("360x180")
        dialog.grab_set()
        dialog.resizable(False, False)

        label = ctk.CTkLabel(dialog, text=message, font=ctk.CTkFont(size=14))
        label.pack(pady=15)

        entry = ctk.CTkEntry(dialog, width=240)
        entry.pack(pady=5)

        result = {}

        def submit():
            result["value"] = entry.get()
            dialog.destroy()

        submit_btn = ctk.CTkButton(dialog, text="Submit", command=submit)
        submit_btn.pack(pady=10)

        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - dialog.winfo_reqwidth()) // 2
        y = (dialog.winfo_screenheight() - dialog.winfo_reqheight()) // 2
        dialog.geometry(f"+{x}+{y}")
        self.wait_window(dialog)
        return result.get("value", "")

    def on_close(self):
        if self.client:
            self.client.close()
        self.destroy()

    def send_files(self):
        selected_files = [card.filename for card in self.file_cards if card.checkbox.get()]
        if not selected_files:
            show_custom_popup("Attention", "Please select at least one file.")
            return

        username = self.logged_in_user or ""
        if not username:
            show_custom_popup("Missing Name", "Username not found.")
            return

        def task():
            self.after(0, lambda: self.send_button.configure(state="disabled"))
            self.after(0, lambda: self.status_label.configure(text="📤 Sending files..."))
            self.after(0, lambda: self.progress.set(0))

            total = len(selected_files)
            try:
                self.client = client_side.PersistentClient(username)
                self.client.connect()

                for i, file in enumerate(selected_files):
                    try:
                        self.client.send_files([file])
                        self.after(0, lambda f=file: show_custom_popup("✅ File Sent", f"{f} sent and confirmed."))
                    except Exception:
                        self.after(0, lambda f=file: show_custom_popup("❌ Failed", f"{f} failed. Try again."))

                    self.after(0, lambda v=(i + 1) / total: self.progress.set(v))

                self.client.pause()
                self.after(0, lambda: self.status_label.configure(text="✅ Done sending files."))
            except Exception as e:
                self.after(0, lambda: show_custom_popup("Connection Error", str(e)))
                self.after(0, lambda: self.status_label.configure(text="⚠️ Server unavailable."))

            self.after(0, lambda: self.send_button.configure(state="normal"))

        threading.Thread(target=task).start()

    def recover_files(self):
        if self.check_recover_process_id:
            return

        self.recover_button.configure(state="disabled")
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()
        self.file_cards.clear()

        self.recover_progress_value = 0
        self.progress.set(0)
        self.status_label.configure(text="🔍 Starting file recovery...")
        self.animate_recovery_progress()

        self.recover_process = multiprocessing.Process(target=run_recovery_process, args=(self.recover_queue,))
        self.recover_process.start()
        self.check_recover_process_id = self.after(100, self.check_recover_process)

    def animate_recovery_progress(self):
        if self.recover_progress_value >= 95:
            self.status_label.configure(text="🧠 Finalizing recovery...")
            return
        increment = random.randint(3, 7)
        self.recover_progress_value = min(95, self.recover_progress_value + increment)

        if self.recover_progress_value < 30:
            self.status_label.configure(text="🔎 Scanning deleted data...")
        elif self.recover_progress_value < 60:
            self.status_label.configure(text="📂 Searching for available files...")
        else:
            self.status_label.configure(text="⚙️ Processing and restoring files...")

        self.progress.set(self.recover_progress_value / 100)
        self.recover_progress_updater_id = self.after(800, self.animate_recovery_progress)

    def check_recover_process(self):
        try:
            msg = self.recover_queue.get_nowait()
        except queue.Empty:
            msg = None

        if msg == "done":
            self.after_cancel(self.check_recover_process_id)
            self.check_recover_process_id = None

            if self.recover_progress_updater_id:
                self.after_cancel(self.recover_progress_updater_id)
                self.recover_progress_updater_id = None

            self.progress.set(1.0)
            self.status_label.configure(text="✅ Recovery complete.")
            self.recover_button.configure(state="normal")
            self.load_recovered_files()
            show_custom_popup("Recovery Complete", "Files recovered successfully!")
        else:
            self.check_recover_process_id = self.after(100, self.check_recover_process)

    def load_recovered_files(self):
        recovered_dir = "recovered_files"
        if not os.path.isdir(recovered_dir):
            show_custom_popup("Error", f"Folder {recovered_dir} not found.")
            return

        files = os.listdir(recovered_dir)
        files = [f for f in files if os.path.isfile(os.path.join(recovered_dir, f))]

        for index, file in enumerate(files):
            icon = get_file_icon(file)
            card = ctk.CTkFrame(self.scroll_frame, border_width=1, corner_radius=10)
            card.grid(row=index // 2, column=index % 2, padx=10, pady=10, sticky="ew")

            label = ctk.CTkLabel(card, text=f"{icon}  {file}", anchor="w", width=200)
            label.pack(side="left", padx=10, pady=5)

            checkbox = ctk.CTkCheckBox(card, text="", width=20)
            checkbox.pack(side="right", padx=10)

            card.checkbox = checkbox
            card.filename = file
            self.file_cards.append(card)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    app = FileRecoveryApp()
    app.mainloop()