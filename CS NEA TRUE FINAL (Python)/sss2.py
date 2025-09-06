# Removed: import json
# Added:
import sqlite3
import hashlib
import os
import re
class UserManager:
    def __init__(self, db_name="users.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self._init_db()

    def _init_db(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def _hash_password(self, password, salt):
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        ).hex()

    def _validate_password_strength(self, password):
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not re.search(r"[A-Z]", password):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"\d", password):
            raise ValueError("Password must contain at least one number")
        if not re.search(r"[!@#$%^&*(),.?:{}|<>]", password):
            raise ValueError("Password must contain at least one special character")

    # Rest of UserManager methods completely changed to use SQL...
    # In all frames, changed:
self.password_entry = ttk.Entry(self, show="*")
# To:
self.password_entry = ttk.Entry(self, show="•")
# In LoginFrame:
self.bind("<Return>", lambda e: self.on_login())

# In SignupFrame:
self.bind("<Return>", lambda e: self.on_signup())

# In ResetPasswordFrame:
self.bind("<Return>", lambda e: self.on_reset())
# In AuthApp.__init__:
frame_name = F.__name__.lower().replace("frame", "")
if frame_name == "resetpassword":
    frame_name = "reset"
self.frames[frame_name] = frame

# In AuthApp.show_frame:
self.root.unbind("<Return>")
if frame_name == "login":
    self.root.bind("<Return>", lambda e: self.frames["login"].on_login())
elif frame_name == "signup":
    self.root.bind("<Return>", lambda e: self.frames["signup"].on_signup())
elif frame_name == "reset":
    self.root.bind("<Return>", lambda e: self.frames["reset"].on_reset())
    # In handle_signup and handle_reset_password:
except ValueError as e:  # Catch password strength errors
    messagebox.showerror("Weak Password", str(e))