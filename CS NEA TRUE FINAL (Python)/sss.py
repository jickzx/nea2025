# Requires Username or email to login 

# # 28/02/2025

# LIBRARIES

import tkinter as tk
from tkinter import ttk, messagebox
import json
from subprocess import call
from abc import ABC, abstractmethod

# Exception classes for user management
class UserAlreadyExists(Exception):
    pass

class InvalidCredentials(Exception):
    pass

class InvalidEmail(Exception):
    pass

class UserNotFound(Exception):
    pass

# User data management
class UserManager:
    def __init__(self, filename="users.json"):
        self.filename = filename
        self.users = self._load_users()

    def _load_users(self):
        try:
            with open(self.filename, 'r') as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_users(self):
        with open(self.filename, 'w') as file:
            json.dump(self.users, file, indent=4)

    def validate_login(self, identifier, password):
        user = None
        if identifier in self.users:
            user = self.users[identifier]
        else:
            for uname, data in self.users.items():
                if data['email'] == identifier:
                    user = data
                    break
        
        if not user or user['password'] != password:
            raise InvalidCredentials("Invalid username or password")
        return True

    def create_user(self, username, email, password):
        if username in self.users:
            raise UserAlreadyExists("Username already exists")
        
        if any(user['email'] == email for user in self.users.values()):
            raise UserAlreadyExists("Email already registered")
        
        if "@" not in email or "." not in email:
            raise InvalidEmail("Invalid email format")
        
        self.users[username] = {
            'email': email,
            'password': password
        }
        self.save_users()

    def reset_password(self, identifier, new_password):
        account = None
        if identifier in self.users:
            account = identifier
        else:
            for uname, data in self.users.items():
                if data['email'] == identifier:
                    account = uname
                    break
        
        if not account:
            raise UserNotFound("No account found with these details")
        
        self.users[account]['password'] = new_password
        self.save_users()

# Base frame class
class BaseFrame(ttk.Frame, ABC):
    def __init__(self, master, controller):
        super().__init__(master)
        self.controller = controller
        self.create_widgets()
        self.grid(row=0, column=0, sticky="nsew")

    @abstractmethod
    def create_widgets(self):
        pass

    @abstractmethod
    def clear_entries(self):
        pass

# Login Frame
class LoginFrame(BaseFrame):
    def create_widgets(self):
        ttk.Label(self, text="Username or Email:").grid(row=0, column=0, padx=30, pady=10)
        self.identifier_entry = ttk.Entry(self)
        self.identifier_entry.grid(row=0, column=1, padx=30, pady=10)
        
        ttk.Label(self, text="Password:").grid(row=1, column=0, padx=30, pady=10)
        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.grid(row=1, column=1, padx=30, pady=10)
        
        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(
            self,
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password
        ).grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)
        
        ttk.Button(self, text="Login", command=self.on_login).grid(row=3, column=1, pady=10)
        
        ttk.Label(self, text="Don't have an account? Sign Up here", 
                foreground="blue", cursor="hand2").grid(row=4, column=0, columnspan=2, pady=10)
        self.bind_links()

    def bind_links(self):
        children = self.winfo_children()
        children[-1].bind("<Button-1>", lambda e: self.controller.show_frame("signup"))
        
        reset_link = ttk.Label(self, text="Forgot Password?", 
                             foreground="red", cursor="hand2")
        reset_link.grid(row=5, column=0, columnspan=2, pady=10)
        reset_link.bind("<Button-1>", lambda e: self.controller.show_frame("reset"))

    def toggle_password(self):
        show = self.show_password_var.get()
        self.password_entry.config(show="" if show else "*")

    def on_login(self):
        identifier = self.identifier_entry.get()
        password = self.password_entry.get()
        self.controller.handle_login(identifier, password)

    def clear_entries(self):
        self.identifier_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

# Signup Frame
class SignupFrame(BaseFrame):
    def create_widgets(self):
        ttk.Label(self, text="Username:").grid(row=0, column=0, padx=10, pady=5)
        self.username_entry = ttk.Entry(self)
        self.username_entry.grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(self, text="Email:").grid(row=1, column=0, padx=10, pady=5)
        self.email_entry = ttk.Entry(self)
        self.email_entry.grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Label(self, text="Password:").grid(row=2, column=0, padx=10, pady=5)
        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.grid(row=2, column=1, padx=10, pady=5)
        
        ttk.Label(self, text="Confirm Password:").grid(row=3, column=0, padx=10, pady=5)
        self.confirm_entry = ttk.Entry(self, show="*")
        self.confirm_entry.grid(row=3, column=1, padx=10, pady=5)
        
        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(
            self,
            text="Show Passwords",
            variable=self.show_password_var,
            command=self.toggle_passwords
        ).grid(row=4, column=1, padx=10, pady=5)
        
        ttk.Button(self, text="Sign Up", command=self.on_signup).grid(row=5, column=1, pady=10)
        
        login_link = ttk.Label(self, text="Already have an account? Login here", 
                            foreground="blue", cursor="hand2")
        login_link.grid(row=6, column=0, columnspan=2, pady=10)
        login_link.bind("<Button-1>", lambda e: self.controller.show_frame("login"))

    def toggle_passwords(self):
        show = self.show_password_var.get()
        self.password_entry.config(show="" if show else "*")
        self.confirm_entry.config(show="" if show else "*")

    def on_signup(self):
        data = {
            'username': self.username_entry.get(),
            'email': self.email_entry.get(),
            'password': self.password_entry.get(),
            'confirm_password': self.confirm_entry.get()
        }
        self.controller.handle_signup(data)

    def clear_entries(self):
        self.username_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.confirm_entry.delete(0, tk.END)

# Reset Password Frame
class ResetPasswordFrame(BaseFrame):
    def create_widgets(self):
        ttk.Label(self, text="Username or Email:").grid(row=0, column=0, padx=10, pady=5)
        self.identifier_entry = ttk.Entry(self)
        self.identifier_entry.grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(self, text="New Password:").grid(row=1, column=0, padx=10, pady=5)
        self.new_password_entry = ttk.Entry(self, show="*")
        self.new_password_entry.grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Label(self, text="Confirm New Password:").grid(row=2, column=0, padx=10, pady=5)
        self.confirm_entry = ttk.Entry(self, show="*")
        self.confirm_entry.grid(row=2, column=1, padx=10, pady=5)
        
        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(
            self,
            text="Show Passwords",
            variable=self.show_password_var,
            command=self.toggle_passwords
        ).grid(row=3, column=1, padx=10, pady=5)
        
        ttk.Button(self, text="Reset Password", command=self.on_reset).grid(row=4, column=1, pady=10)
        
        back_link = ttk.Label(self, text="Back to Login", 
                            foreground="blue", cursor="hand2")
        back_link.grid(row=5, column=0, columnspan=2, pady=10)
        back_link.bind("<Button-1>", lambda e: self.controller.show_frame("login"))

    def toggle_passwords(self):
        show = self.show_password_var.get()
        self.new_password_entry.config(show="" if show else "*")
        self.confirm_entry.config(show="" if show else "*")

    def on_reset(self):
        data = {
            'identifier': self.identifier_entry.get(),
            'new_password': self.new_password_entry.get(),
            'confirm_password': self.confirm_entry.get()
        }
        self.controller.handle_reset_password(data)

    def clear_entries(self):
        self.identifier_entry.delete(0, tk.END)
        self.new_password_entry.delete(0, tk.END)
        self.confirm_entry.delete(0, tk.END)

# Main Application
class AuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Authentication System")
        self.root.geometry("500x500")
        self.root.resizable(True, True)
        
        self.user_manager = UserManager()
        
        self.frames = {}
        for F in (LoginFrame, SignupFrame, ResetPasswordFrame):
            frame = F(root, self)
            self.frames[F.__name__.lower().replace("frame", "")] = frame
        
        self.show_frame("login")

    def show_frame(self, frame_name):
        frame = self.frames[frame_name]
        self.root.title(f"{frame_name.capitalize()} Section")
        frame.tkraise()
        frame.clear_entries()

    def handle_login(self, identifier, password):
        try:
            if not identifier or not password:
                raise ValueError("Please fill in both fields")
            
            self.user_manager.validate_login(identifier, password)
            messagebox.showinfo("Success", "Login successful!")
            self.root.destroy()
            call(["python", "Main.py"])
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def handle_signup(self, data):
        try:
            if not all(data.values()):
                raise ValueError("All fields are required")
            
            if data['password'] != data['confirm_password']:
                raise ValueError("Passwords don't match")
            
            self.user_manager.create_user(
                data['username'],
                data['email'],
                data['password']
            )
            messagebox.showinfo("Success", "Account created successfully!")
            self.show_frame("login")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def handle_reset_password(self, data):
        try:
            if not all(data.values()):
                raise ValueError("All fields are required")
            
            if data['new_password'] != data['confirm_password']:
                raise ValueError("Passwords don't match")
            
            self.user_manager.reset_password(
                data['identifier'],
                data['new_password']
            )
            messagebox.showinfo("Success", "Password updated successfully!")
            self.show_frame("login")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = AuthApp(root)
    root.mainloop()
