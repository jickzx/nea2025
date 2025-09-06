import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib
import os 
import re
from abc import ABC, abstractmethod
import csv

# Exception classes for user management
class UserAlreadyExists(Exception):
    pass

class InvalidCredentials(Exception):
    pass

class InvalidEmail(Exception):
    pass

class UserNotFound(Exception):
    pass

class PasswordSameAsOld(Exception):
    pass

class WelcomeScreen:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Welcome!")
        self.root.geometry("500x250")  # Increased height to accommodate new button
        self.root.resizable(False, False)
        
        self.create_widgets()
        self.root.mainloop()
    
    def create_widgets(self):
        # Welcome message
        welcome_label = ttk.Label(
            self.root,
            text="Welcome to St Thomas More's \n Student University Application!",
            font=("Helvetica", 16)
        )
        welcome_label.pack(pady=20)
        
        # Description
        desc_label = ttk.Label(
            self.root,
            text="Please login or signup to continue",
            font=("Helvetica", 12)
        )
        desc_label.pack(pady=10)
        
        # Start button
        start_btn = ttk.Button(
            self.root,
            text="Get Started",
            command=self.launch_auth
        )
        start_btn.pack(pady=10)
        
        # Instructions button
        instructions_btn = ttk.Button(
            self.root,
            text="Instructions",
            command=self.show_instructions
        )
        instructions_btn.pack(pady=10)
    
    def launch_auth(self):
        self.root.destroy()  # Close the welcome screen
        root = tk.Tk()
        app = AuthApp(root)
        root.mainloop()
    
    def show_instructions(self):
        # Create new window
        instructions_window = tk.Toplevel(self.root)
        instructions_window.title("Application Instructions")
        instructions_window.geometry("400x300")
        
        # Create instruction buttons
        instructions = {
            "Login Instructions": "When you finish signing up, you will be taken back to the login page. This login page requires you to enter your (username or email) and password. If you have forgotten your password, you can reset it by clicking the 'Forgot Password' button.",
            "Sign Up Instructions": "First, you will need to sign up to this program. You need to add an email address, create a username, create a password and confirm that password. If the passwords do not match, it will invalidate the sign up process but not get rid of your details.",
            "Reset Password Instructions": "This is located underneath the login button. You will need to enter your email address or your username, and create a new password, then confirm that password. If any of the information doesn't match, it will invalidate the reset process but not get rid of your details. Remember your new password!",
            "Main Menu Instructions": "This is where you can access the Degree Apprenticeships and Universities. You can also log out if you need to.",
            "Application Instructions - University": "Here, you need to fill in your grades, and what subjects you do, as well as 5 universities you want to go to. You can select the firm and insurance. Then, you will see others grades and what subjects they did, as well as whether they got accepted or rejected. This should also create a probability of you getting in.",
            "Application Instructions - Degree Apprenticeships": "Here, you need to fill in the grades you got in your subject, as well as the degree apprenticeship you are planning to apply for.",
        }
        
        for text, message in instructions.items():
            btn = ttk.Button(
                instructions_window,
                text=text,
                command=lambda msg=message: messagebox.showinfo(text, msg)
            )
            btn.pack(pady=3, fill=tk.X, padx=20)

# User data management
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
        """Password strength checker using regex patterns"""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not re.search(r"[A-Z]", password):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"\d", password):
            raise ValueError("Password must contain at least one number")
        if not re.search(r"[!@#$%^&*(),.?:{}|<>]", password):
            raise ValueError("Password must contain at least one special character")

    def validate_login(self, identifier, password):
        self.cursor.execute("""
            SELECT username, password_hash, salt FROM users 
            WHERE username = ? OR email = ?
        """, (identifier, identifier))
        user = self.cursor.fetchone()
        
        if not user:
            raise InvalidCredentials("Invalid username or password")
        
        stored_hash = user[1]
        salt = bytes.fromhex(user[2])
        input_hash = self._hash_password(password, salt)
        
        if input_hash != stored_hash:
            raise InvalidCredentials("Invalid username or password")
        return True

    def create_user(self, username, email, password):
        try:
            self._validate_password_strength(password)
            salt = os.urandom(16)
            hashed_password = self._hash_password(password, salt)
            
            self.cursor.execute("""
                INSERT INTO users (username, email, password_hash, salt)
                VALUES (?, ?, ?, ?)
            """, (username, email, hashed_password, salt.hex()))
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed: users.username" in str(e):
                raise UserAlreadyExists("Username already exists")
            elif "UNIQUE constraint failed: users.email" in str(e):
                raise UserAlreadyExists("Email already registered")
            else:
                raise

    def reset_password(self, identifier, new_password):
        self._validate_password_strength(new_password)
        self.cursor.execute("""
            SELECT username, salt, password_hash FROM users 
            WHERE username = ? OR email = ?
        """, (identifier, identifier))
        result = self.cursor.fetchone()
        
        if not result:
            raise UserNotFound("No account found with these details")
        
        username, salt_hex, old_hash = result
        salt = bytes.fromhex(salt_hex)
        new_hash = self._hash_password(new_password, salt)
        
        if new_hash == old_hash:
            raise PasswordSameAsOld("New password cannot be the same as the old password.")
        
        self.cursor.execute("""
            UPDATE users 
            SET password_hash = ?
            WHERE username = ?
        """, (new_hash, username))
        self.conn.commit()

        
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
        self.password_entry = ttk.Entry(self, show="•")
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

        # Bind Enter key to login
        self.bind("<Return>", lambda e: self.on_login())

        # Centring widgets
        self.grid_rowconfigure(0, weight=1)  # Top spacing
        self.grid_rowconfigure(5, weight=1)  # Bottom spacing
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

    def bind_links(self):
        children = self.winfo_children()
        children[-1].bind("<Button-1>", lambda e: self.controller.show_frame("signup"))
        
        reset_link = ttk.Label(self, text="Forgotten Password?", 
                             foreground="red", cursor="hand2")
        reset_link.grid(row=5, column=0, columnspan=2, pady=10)
        reset_link.bind("<Button-1>", lambda e: self.controller.show_frame("reset"))

    def toggle_password(self):
        show = self.show_password_var.get()
        self.password_entry.config(show="" if show else "•")

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
        self.password_entry = ttk.Entry(self, show="•")
        self.password_entry.grid(row=2, column=1, padx=10, pady=5)
        
        ttk.Label(self, text="Confirm Password:").grid(row=3, column=0, padx=10, pady=5)
        self.confirm_entry = ttk.Entry(self, show="•")
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

        # Bind Enter key to signup
        self.bind("<Return>", lambda e: self.on_signup())

        # Centring widgets
        self.grid_rowconfigure(0, weight=1)  # Top spacing
        self.grid_rowconfigure(7, weight=1)  # Bottom spacing
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

    def toggle_passwords(self):
        show = self.show_password_var.get()
        self.password_entry.config(show="" if show else "•")
        self.confirm_entry.config(show="" if show else "•")

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
        self.new_password_entry = ttk.Entry(self, show="•")
        self.new_password_entry.grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Label(self, text="Confirm New Password:").grid(row=2, column=0, padx=10, pady=5)
        self.confirm_entry = ttk.Entry(self, show="•")
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

        # Bind Enter key to reset password
        self.bind("<Return>", lambda e: self.on_reset())

        # Centring Widgets
        self.grid_rowconfigure(0, weight=1)  # Top spacing
        self.grid_rowconfigure(5, weight=1)  # Bottom spacing
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

    def toggle_passwords(self):
        show = self.show_password_var.get()
        self.new_password_entry.config(show="" if show else "•")
        self.confirm_entry.config(show="" if show else "•")

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

# App Menu Frame
class AppMenuFrame(BaseFrame):
    def create_widgets(self):
        ttk.Button(self, text="Degree Apprenticeships", command=self.on_degree_apprenticeships).grid(row=0, column=0, padx=10, pady=10)
        ttk.Button(self, text="Universities", command=self.on_universities).grid(row=1, column=0, padx=10, pady=10)
        ttk.Button(self, text="Log Out", command=self.on_logout).grid(row=2, column=0, padx=10, pady=10)

        # Centring widgets
        self.grid_rowconfigure(0, weight=1)  # Top spacing
        self.grid_rowconfigure(3, weight=1)  # Bottom spacing
        self.grid_columnconfigure(0, weight=1)

    def on_degree_apprenticeships(self):
        self.controller.show_apprenticeship_app()

    def on_universities(self):
        self.controller.show_university_app()

    def on_logout(self):
        self.controller.show_frame("login")

    def clear_entries(self):
        pass  # No entries to clear in this frame

# Main Application
class AuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Authentication System")
        self.root.geometry("1000x600")
        self.root.resizable(True, True)
        self.user_manager = UserManager()
    
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        self.frames = {}
        for F in (LoginFrame, SignupFrame, ResetPasswordFrame, AppMenuFrame):  # Add AppMenuFrame here
            frame = F(root, self)
            frame_name = F.__name__.lower().replace("frame", "")
            if frame_name == "resetpassword":
                frame_name = "reset"
            self.frames[frame_name] = frame
        
        self.current_frame = None
        self.show_frame("login")
        
        # Set up Enter key binding for the whole window
        self.current_frame = None
        self.show_frame("login")

    def show_frame(self, frame_name):
        if self.current_frame:
            self.root.unbind("<Return>")  # Remove previous binding
            
        self.current_frame = frame_name
        frame = self.frames[frame_name]
        self.root.title(f"{frame_name.capitalize()} System") # Login / Sign Up / Reset Password System
        frame.tkraise()
        frame.clear_entries()
        
        # Bind Enter key 
        if frame_name == "login":
            self.root.bind("<Return>", lambda e: self.frames["login"].on_login())
        elif frame_name == "signup":
            self.root.bind("<Return>", lambda e: self.frames["signup"].on_signup())
        elif frame_name == "reset":
            self.root.bind("<Return>", lambda e: self.frames["reset"].on_reset())

    def handle_login(self, identifier, password):
        try:
            if not identifier or not password:
                raise ValueError("Please fill in both fields")
            
            self.user_manager.validate_login(identifier, password)
            messagebox.showinfo("Success", "Login successful!")
            self.show_frame("appmenu")  # Redirect to App Menu after successful login
            
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
            
        except ValueError as e:  # Catch password strength errors
            messagebox.showerror("Weak Password", str(e))
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
            
        except PasswordSameAsOld as e:
            messagebox.showerror("Password Error", str(e))
        except ValueError as e:  # Catch password strength errors
            messagebox.showerror("Weak Password", str(e))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_university_app(self):
        self.root.withdraw()  # Hide the auth window
        university_app = UniversityApplication(self.root)
        university_app.protocol("WM_DELETE_WINDOW", lambda: self.on_child_close(university_app))
        university_app.mainloop()

    def show_apprenticeship_app(self):
        self.root.withdraw()  # Hide the auth window
        apprenticeship_app = ApprenticeshipApplication(self.root)
        apprenticeship_app.protocol("WM_DELETE_WINDOW", lambda: self.on_child_close(apprenticeship_app))
        apprenticeship_app.mainloop()

    def on_child_close(self, child_window):
        child_window.destroy()
        self.root.deiconify()  # Show the auth window again

# University Application Classes
class Student:
    def __init__(self, universities, firm, insurance, subjects, grades, status, gcse_subjects=None, gcse_grades=None, extracurriculars=None, supercurriculars=None):
        self.universities = universities
        self.firm = firm
        self.insurance = insurance
        self.subjects = subjects
        self.grades = grades
        self.status = status
        self.gcse_subjects = gcse_subjects if gcse_subjects else []
        self.gcse_grades = gcse_grades if gcse_grades else []
        self.extracurriculars = extracurriculars if extracurriculars else []
        self.supercurriculars = supercurriculars if supercurriculars else []

class StudentProfile(Student):
    """Extended student class for the current user's profile with additional methods"""
    def calculate_gcse_score(self):
        """Convert GCSE grades to numerical values for analysis"""
        grade_points = {'9':9, '8':8, '7':7, '6':6, '5':5, '4':4, 
                       '3':3, '2':2, '1':1, 'U':0}
        return sum(grade_points.get(grade, 0) for grade in self.gcse_grades)
    
    def get_profile_dict(self):
        """Convert profile to dictionary for saving/analysis"""
        return {
            'universities': self.universities,
            'firm': self.firm,
            'insurance': self.insurance,
            'subjects': self.subjects,
            'grades': self.grades,
            'status': "Current Applicant",
            'gcse_subjects': self.gcse_subjects,
            'gcse_grades': self.gcse_grades,
            'extracurriculars': self.extracurriculars,
            'supercurriculars': self.supercurriculars
        }

class DataManager:
    def __init__(self):
        self.students = []
        self.data_loaded = False

    def load_data(self, filename):
        try:
            with open(filename, 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    student = Student(
                        row['universities'].split(','),
                        row['firm'],
                        row['insurance'],
                        row['subjects'].split(','),
                        row['grades'].split(','),
                        row['status'],
                        row.get('gcse_subjects', '').split(','),
                        row.get('gcse_grades', '').split(','),
                        row.get('extracurriculars', '').split(','),
                        row.get('supercurriculars', '').split(',')
                    )
                    self.students.append(student)
            self.data_loaded = True
            return True
        except FileNotFoundError:
            self.data_loaded = False
            return False

    def save_student(self, filename, student):
        file_exists = os.path.isfile(filename)
        with open(filename, 'a', newline='') as file:
            fieldnames = ['universities', 'firm', 'insurance', 'subjects', 'grades', 
                        'status', 'gcse_subjects', 'gcse_grades', 
                        'extracurriculars', 'supercurriculars']
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow({
                'universities': ','.join(student.universities),
                'firm': student.firm,
                'insurance': student.insurance,
                'subjects': ','.join(student.subjects),
                'grades': ','.join(student.grades),
                'status': student.status,
                'gcse_subjects': ','.join(student.gcse_subjects),
                'gcse_grades': ','.join(student.gcse_grades),
                'extracurriculars': ','.join(student.extracurriculars),
                'supercurriculars': ','.join(student.supercurriculars)
            })

class ValidationHelper:
    def __init__(self, analyser):
        self.analyser = analyser

    def validate_unis(self, selected_unis):
        selected = [uni for uni in selected_unis if uni]
        duplicates = set([x for x in selected if selected.count(x) > 1])
        oxbridge = {"Cambridge", "Oxford"}.intersection(selected)
        
        if duplicates:
            return (False, f"Duplicate universities: {', '.join(duplicates)}")
        if len(oxbridge) > 1:
            return (False, "Cannot select both Oxford and Cambridge!")
        return (True, "")

    def validate_firm_insurance(self, firm, insurance, selected_unis):
        if not firm or not insurance:
            return (False, "Please select both Firm and Insurance choices")
        if firm == insurance:
            return (False, "Firm and Insurance choices cannot be the same")
        if firm not in selected_unis or insurance not in selected_unis:
            return (False, "Choices must be from your selected universities")
        return (True, "")

    def validate_grades(self, subjects, grades, a_level_grades, btec_grades):
        # Check first 3 subjects are mandatory
        if len([sub for sub in subjects[:3] if sub]) < 3:
            return (False, "First 3 A-Level subjects are mandatory!")
        
        # Check first 3 grades are mandatory
        if len([grade for grade in grades[:3] if grade]) < 3:
            return (False, "First 3 A-Level grades are mandatory!")
        
        # Validate grade types match subject types
        for i, (subject, grade) in enumerate(zip(subjects, grades)):
            if subject and grade:
                is_btec = "BTEC" in subject
                if is_btec and grade not in btec_grades:
                    return (False, 
                        f"BTEC subjects must use BTEC grades\nError in row {i+1}: {subject} - {grade}")
                elif not is_btec and grade not in a_level_grades:
                    return (False, 
                        f"A-Level subjects must use A-Level grades\nError in row {i+1}: {subject} - {grade}")
        return (True, "")

    def validate_gcse(self, gcse_subjects, gcse_grades):
        mandatory_subjects = ["Maths", "English Language", "English Literature"]
        entered_subjects = gcse_subjects[:3]
        
        # Check if all mandatory subjects are present
        missing_mandatory = []
        for i, subject in enumerate(mandatory_subjects):
            if entered_subjects[i] != subject:
                missing_mandatory.append(subject)
        
        if missing_mandatory:
            return (False, 
                f"Mandatory GCSE subjects missing: {', '.join(missing_mandatory)}")
        
        # Check first 3 grades are entered
        if len([grade for grade in gcse_grades[:3] if grade]) < 3:
            return (False, "First 3 GCSE grades are mandatory!")
            
        return (True, "")

class ReportGenerator:
    def __init__(self, analyser):
        self.analyser = analyser

    def generate_student_report(self, student_profile, students):
        report = {
            'firm': self._generate_university_report(student_profile.firm, students),
            'insurance': self._generate_university_report(student_profile.insurance, students),
            'other': self._generate_other_unis_report(student_profile, students)
        }
        return report

    def _generate_university_report(self, university, students):
        uni_students = [s for s in students if university in s.universities]
        if not uni_students:
            return f"No historical data found for {university}"
        
        success_rate = sum(1 for s in uni_students if s.status == "Accepted") / len(uni_students)
        report = [
            f"University: {university}",
            f"Historical Acceptance Rate: {success_rate:.1%}",
            "--------------------------------------------------",
            "Successful applicants typically had:"
        ]
        
        # Add grade analysis
        avg_grades = self._calculate_avg_grades(uni_students)
        report.append(f"- A-Level grades: {avg_grades}")
        
        # Add GCSE analysis if available
        if any(s.gcse_grades for s in uni_students):
            avg_gcse = self._calculate_avg_gcse(uni_students)
            report.append(f"- GCSE average score: {avg_gcse:.1f}")
        
        return '\n'.join(report)

    def _generate_other_unis_report(self, student_profile, students):
        selected_unis = student_profile.universities
        other_students = [
            s for s in students 
            if any(uni in s.universities for uni in selected_unis)
            and s.firm != student_profile.firm
            and s.insurance != student_profile.insurance
        ]
        
        if not other_students:
            return "No comparable data for other selected universities"
        
        report = ["Other University Choices Analysis:", "-------------------------------"]
        for uni in student_profile.universities:
            if uni not in [student_profile.firm, student_profile.insurance]:
                uni_students = [s for s in other_students if uni in s.universities]
                if uni_students:
                    success_rate = sum(1 for s in uni_students if s.status == "Accepted") / len(uni_students)
                    report.append(f"{uni}: {success_rate:.1%} acceptance rate")
        
        return '\n'.join(report)

    def _calculate_avg_grades(self, students):
        grade_points = {'A*':6, 'A':5, 'B':4, 'C':3, 'D':2, 'E':1, 'U':0,
                       'Distinction*':6, 'Distinction':5, 'Merit':4, 'Pass':3}
        total = 0
        count = 0
        for student in students:
            for grade in student.grades:
                if grade in grade_points:
                    total += grade_points[grade]
                    count += 1
        return f"{total/count:.1f} average points" if count > 0 else "No grade data"

    def _calculate_avg_gcse(self, students):
        grade_points = {'9':9, '8':8, '7':7, '6':6, '5':5, '4':4, 
                       '3':3, '2':2, '1':1, 'U':0}
        total = 0
        count = 0
        for student in students:
            for grade in student.gcse_grades:
                if grade in grade_points:
                    total += grade_points[grade]
                    count += 1
        return total/count if count > 0 else 0

class GradeAnalyser:
    def __init__(self):
        self.data_manager = DataManager()
        self.validation = ValidationHelper(self)
        self.report_generator = ReportGenerator(self)
        self.all_subjects = [
            "Art", "Biology", "Business", "BTEC ICT Level 3", "BTEC Sport Level 3", 
            "BTEC Music Level 3", "Chemistry", "Computer Science", "English Language", 
            "English Literature", "Extended Project Qualification", "Film Studies", 
            "Geography", "History", "Mathematics", "Core Mathematics", "Further Mathematics", 
            "Media Studies", "Physics", "Politics", "Psychology", "Religious Education", 
            "Sociology", "Spanish",
        ]
        self.gcse_subjects = [
            "Maths", "English Language", "English Literature", "Science", 
            "History", "Geography", "French", "Spanish", "German", "Computer Science",
            "Religious Studies", "Art", "Drama", "Music", "Physical Education",
            "Business Studies", "Statistics", "Additional Science"
        ]
        self.extracurricular_options = [
            "Sports", "Music", "Drama", "Debating", "Volunteering",
            "Student Council", "Duke of Edinburgh", "Part-time Job",
            "School Prefect", "Mentoring", "None"
        ]
        self.supercurricular_options = [
            "Subject Olympiads", "University Summer Schools", "MOOCs",
            "Subject-related Competitions", "Academic Clubs", "Research Projects",
            "Subject-related Reading", "None"
        ]
        self.a_level_grades = ["A*", "A", "B", "C", "D", "E", "U"]
        self.btec_grades = ["Distinction*", "Distinction", "Merit", "Pass", "U"]
        self.gcse_grades = ["9", "8", "7", "6", "5", "4", "3", "2", "1", "U"]
    
    @property
    def students(self):
        return self.data_manager.students
    
    def load_data(self, filename):
        return self.data_manager.load_data(filename)

class UniversityApplication(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("University Application Assistant")
        self.geometry("800x600")
        self.analyser = GradeAnalyser()
        self.current_step = 1
        self.selected_unis = [tk.StringVar() for _ in range(5)]
        self.create_widgets()
        self.load_data()
        
    def load_data(self):
        if not self.analyser.load_data("university_data.csv"):
            messagebox.showwarning("Data Error", "Historical data not found! Some features may be limited.")
            
    def create_widgets(self):
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        self.uni_frame = ttk.Frame(self.main_frame)
        self.firm_insurance_frame = ttk.Frame(self.main_frame)
        self.grades_frame = ttk.Frame(self.main_frame)
        self.gcse_frame = ttk.Frame(self.main_frame)
        self.activities_frame = ttk.Frame(self.main_frame)
        
        self.create_uni_step()
        self.create_firm_insurance_step()
        self.create_grades_step()
        self.create_gcse_step()
        self.create_activities_step()
        self.show_current_step()
        
    def show_current_step(self):
        frames = [self.uni_frame, self.firm_insurance_frame, self.grades_frame, 
                 self.gcse_frame, self.activities_frame]
        for i, frame in enumerate(frames):
            frame.pack() if i == self.current_step - 1 else frame.pack_forget()

    def create_uni_step(self):
        uni_list = [
            "Oxford", "Cambridge", "Imperial College London", "UCL", "LSE", 
            "Warwick", "Manchester", "Bristol", "Edinburgh", "King's College London", 
            "East Anglia", "Birmingham", "Exeter", "Queen Mary University London", 
            "Nottingham", "Southampton", "Newcastle", "Leeds", "Bath", "Reading", 
            "Essex", "Middlesex", "Sussex", "Birmingham City", "Nottingham Trent", 
            "Cardiff", "Surrey", "Coventry", "Swansea", "City, University of London", 
            "Goldsmiths, University of London", "University of Greenwich"
        ]
        
        ttk.Label(self.uni_frame, text="Step 1: Select 5 Universities", font=('Arial', 14)).pack(pady=10)
    
        self.uni_combos = []
        for i in range(5):
            frame = ttk.Frame(self.uni_frame)
            frame.pack(pady=5)
            ttk.Label(frame, text=f"Choice {i+1}:").pack(side=tk.LEFT)
            
            combo = ttk.Combobox(
                frame, 
                values=uni_list, 
                textvariable=self.selected_unis[i], 
                width=30
            )
            combo.pack(side=tk.LEFT)
            combo.bind("<KeyRelease>", lambda event, cb=combo: self.auto_complete(event, cb, uni_list))
            self.uni_combos.append(combo)
            
        ttk.Button(self.uni_frame, text="Next →", command=self.next_step).pack(pady=20)

    def create_firm_insurance_step(self):
        ttk.Label(self.firm_insurance_frame, text="Step 2: Select Firm and Insurance Choices", font=('Arial', 14)).pack(pady=10)
        
        self.firm_var = tk.StringVar()
        self.insurance_var = tk.StringVar()
        
        firm_frame = ttk.Frame(self.firm_insurance_frame)
        firm_frame.pack(pady=10)
        ttk.Label(firm_frame, text="Firm Choice:").pack(side=tk.LEFT)
        self.firm_combo = ttk.Combobox(firm_frame, textvariable=self.firm_var, width=25, state="readonly")
        self.firm_combo.pack(side=tk.LEFT, padx=10)
        
        insurance_frame = ttk.Frame(self.firm_insurance_frame)
        insurance_frame.pack(pady=10)
        ttk.Label(insurance_frame, text="Insurance Choice:").pack(side=tk.LEFT)
        self.insurance_combo = ttk.Combobox(insurance_frame, textvariable=self.insurance_var, width=25, state="readonly")
        self.insurance_combo.pack(side=tk.LEFT, padx=10)
        
        button_frame = ttk.Frame(self.firm_insurance_frame)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="← Back", command=self.prev_step).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Next →", command=self.next_step).pack(side=tk.RIGHT, padx=10)

    def auto_complete(self, event, combo, options_list):
        value = event.widget.get()
        combo['values'] = [item for item in options_list if value.lower() in item.lower()]
        combo.event_generate('<Down>')
        return "break"

    def create_grades_step(self):
        self.subject_vars = [tk.StringVar() for _ in range(5)]
        self.grade_vars = [tk.StringVar() for _ in range(5)]
        
        ttk.Label(self.grades_frame, text="Step 3: A-Level Subjects & Grades", font=('Arial', 14)).pack(pady=10)
        
        for i in range(5):
            frame = ttk.Frame(self.grades_frame)
            frame.pack(pady=5)
            
            sub_combo = ttk.Combobox(frame, values=self.analyser.all_subjects, 
                                   textvariable=self.subject_vars[i], width=30)
            sub_combo.pack(side=tk.LEFT, padx=5)
            sub_combo.bind("<KeyRelease>", lambda event, cb=sub_combo: self.auto_complete(event, cb, self.analyser.all_subjects))
            
            grade_combo = ttk.Combobox(frame, values=self.analyser.a_level_grades + self.analyser.btec_grades, 
                                     textvariable=self.grade_vars[i], width=10)
            grade_combo.pack(side=tk.LEFT)
            grade_combo.bind("<KeyRelease>", lambda event, cb=grade_combo: self.auto_complete(event, cb, self.analyser.a_level_grades + self.analyser.btec_grades))
            
            if i < 3:
                ttk.Label(frame, text="*", foreground="red").pack(side=tk.LEFT)
                
        ttk.Button(self.grades_frame, text="← Back", command=self.prev_step).pack(side=tk.LEFT, padx=10)
        ttk.Button(self.grades_frame, text="Next →", command=self.next_step).pack(side=tk.RIGHT, padx=10)

    def create_gcse_step(self):
        self.gcse_subject_vars = [tk.StringVar() for _ in range(13)]
        self.gcse_grade_vars = [tk.StringVar() for _ in range(13)]
        
        # Set default values for first 3 subjects
        self.gcse_subject_vars[0].set("Maths")
        self.gcse_subject_vars[1].set("English Language")
        self.gcse_subject_vars[2].set("English Literature")
        
        ttk.Label(self.gcse_frame, text="Step 4: GCSE Subjects & Grades", font=('Arial', 14)).pack(pady=10)
        
        for i in range(13):
            frame = ttk.Frame(self.gcse_frame)
            frame.pack(pady=5)
            
            sub_combo = ttk.Combobox(frame, values=self.analyser.gcse_subjects, 
                                textvariable=self.gcse_subject_vars[i], width=25)
            sub_combo.pack(side=tk.LEFT, padx=5)
            sub_combo.bind("<KeyRelease>", lambda event, cb=sub_combo: self.auto_complete(event, cb, self.analyser.gcse_subjects))
            
            grade_combo = ttk.Combobox(frame, values=self.analyser.gcse_grades, 
                                    textvariable=self.gcse_grade_vars[i], width=5)
            grade_combo.pack(side=tk.LEFT)
            grade_combo.bind("<KeyRelease>", lambda event, cb=grade_combo: self.auto_complete(event, cb, self.analyser.gcse_grades))
            
            if i < 3:
                ttk.Label(frame, text="*", foreground="red").pack(side=tk.LEFT)
        
        ttk.Button(self.gcse_frame, text="← Back", command=self.prev_step).pack(side=tk.LEFT, padx=10)
        ttk.Button(self.gcse_frame, text="Next →", command=self.next_step).pack(side=tk.RIGHT, padx=10)

    def create_activities_step(self):
        ttk.Label(self.activities_frame, text="Step 5: Extracurriculars & Supercurriculars (Optional)", 
                font=('Arial', 14)).pack(pady=10)
        
        # Extracurriculars section
        extracurricular_frame = ttk.Frame(self.activities_frame)
        extracurricular_frame.pack(pady=10)
        ttk.Label(extracurricular_frame, text="Extracurricular Activities:", 
                font=('Arial', 10, 'bold')).pack()
        
        self.extracurricular_vars = [tk.StringVar(value="None") for _ in range(3)]
        for i in range(3):
            frame = ttk.Frame(extracurricular_frame)
            frame.pack(pady=5)
            ttk.Label(frame, text=f"Activity {i+1}:").pack(side=tk.LEFT)
            combo = ttk.Combobox(frame, values=self.analyser.extracurricular_options, 
                            textvariable=self.extracurricular_vars[i], width=30)
            combo.pack(side=tk.LEFT, padx=5)
            combo.bind("<KeyRelease>", lambda event, cb=combo: self.auto_complete(event, cb, self.analyser.extracurricular_options))
            
        # Supercurriculars section 
        supercurricular_frame = ttk.Frame(self.activities_frame)
        supercurricular_frame.pack(pady=10)
        ttk.Label(supercurricular_frame, text="Supercurricular Activities:", 
                font=('Arial', 10, 'bold')).pack()
        
        self.supercurricular_vars = [tk.StringVar(value="None") for _ in range(3)]
        for i in range(3):
            frame = ttk.Frame(supercurricular_frame)
            frame.pack(pady=5)
            ttk.Label(frame, text=f"Activity {i+1}:").pack(side=tk.LEFT)
            combo = ttk.Combobox(frame, values=self.analyser.supercurricular_options, 
                            textvariable=self.supercurricular_vars[i], width=30)
            combo.pack(side=tk.LEFT, padx=5)
            combo.bind("<KeyRelease>", lambda event, cb=combo: self.auto_complete(event, cb, self.analyser.supercurricular_options))
            
        # Buttons
        button_frame = ttk.Frame(self.activities_frame)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="← Back", command=self.prev_step).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Generate Report", command=self.generate_report).pack(side=tk.RIGHT, padx=10)

    def next_step(self):
        if self.current_step == 1:
            selected = [var.get() for var in self.selected_unis if var.get()]
            valid, msg = self.analyser.validation.validate_unis(selected)
            if not valid:
                messagebox.showerror("Error", msg)
                return
            if len(selected) < 5:
                messagebox.showerror("Error", "Please select all 5 universities")
                return
            self.firm_combo['values'] = selected
            self.insurance_combo['values'] = selected
            self.current_step = 2
            
        elif self.current_step == 2:
            valid, msg = self.analyser.validation.validate_firm_insurance(
                self.firm_var.get(),
                self.insurance_var.get(),
                [var.get() for var in self.selected_unis]
            )
            if not valid:
                messagebox.showerror("Error", msg)
                return
            self.current_step = 3
            
        elif self.current_step == 3:
            valid, msg = self.analyser.validation.validate_grades(
                [var.get() for var in self.subject_vars],
                [var.get() for var in self.grade_vars],
                self.analyser.a_level_grades,
                self.analyser.btec_grades
            )
            if not valid:
                messagebox.showerror("Error", msg)
                return
            self.current_step = 4
            
        elif self.current_step == 4:
            valid, msg = self.analyser.validation.validate_gcse(
                [var.get() for var in self.gcse_subject_vars],
                [var.get() for var in self.gcse_grade_vars]
            )
            if not valid:
                messagebox.showerror("Error", msg)
                return
            self.current_step = 5
            
        self.show_current_step()

    def prev_step(self):
        self.current_step = max(1, self.current_step - 1)
        self.show_current_step()

    def generate_report(self):
        # Create student profile
        student = StudentProfile(
            universities=[var.get() for var in self.selected_unis],
            firm=self.firm_var.get(),
            insurance=self.insurance_var.get(),
            subjects=[var.get() for var in self.subject_vars if var.get()],
            grades=[var.get() for var in self.grade_vars if var.get()],
            status="Current Applicant",
            gcse_subjects=[var.get() for var in self.gcse_subject_vars if var.get()],
            gcse_grades=[var.get() for var in self.gcse_grade_vars if var.get()],
            extracurriculars=[var.get() for var in self.extracurricular_vars 
                            if var.get() and var.get() != "None"],
            supercurriculars=[var.get() for var in self.supercurricular_vars 
                            if var.get() and var.get() != "None"]
        )
        
        # Ask user if they want to save their data
        save_data = messagebox.askyesno(
            "Save Data", 
            "Would you like to save your data to the database for future reference?"
        )
        
        if save_data:
            # Save the student data
            self.analyser.data_manager.save_student("university_data.csv", student)
            messagebox.showinfo("Success", "Your data has been saved successfully!")
        
        # Generate report
        report = self.analyser.report_generator.generate_student_report(
            student, 
            self.analyser.students
        )
        
        # Display report in the new format
        report_win = tk.Toplevel()
        report_win.title("University Application Report")
        report_win.geometry("800x700")
        
        # Main container frame with scrollbar
        main_frame = ttk.Frame(report_win)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Header
        ttk.Label(
            scrollable_frame, 
            text="University Application Report", 
            font=('Arial', 16, 'bold')
        ).pack(pady=(10, 5), anchor='w')
        
        # University choices section
        ttk.Label(
            scrollable_frame, 
            text="University Choices", 
            font=('Arial', 12, 'bold')
        ).pack(pady=(5, 0), anchor='w')
        
        # Firm and Insurance
        choices_text = f"Firm: {student.firm}"
        if student.insurance:
            choices_text += f"\nInsurance: {student.insurance}"
        ttk.Label(
            scrollable_frame, 
            text=choices_text,
            font=('Arial', 10)
        ).pack(anchor='w', padx=10)
        
        # Other choices
        other_unis = [uni for uni in student.universities 
                    if uni not in (student.firm, student.insurance)]
        if other_unis:
            ttk.Label(
                scrollable_frame, 
                text=f"Other choices: {', '.join(other_unis)}",
                font=('Arial', 10)
            ).pack(anchor='w', padx=10)
        
        # Separator
        ttk.Separator(scrollable_frame).pack(fill='x', pady=10)
        
        # A-Level subjects section
        ttk.Label(
            scrollable_frame, 
            text="A-Level Subjects", 
            font=('Arial', 12, 'bold')
        ).pack(anchor='w')
        
        for subject, grade in zip(student.subjects, student.grades):
            if subject:
                ttk.Label(
                    scrollable_frame, 
                    text=f"- {subject}: {grade}",
                    font=('Arial', 10)
                ).pack(anchor='w', padx=20)
        
        # Separator
        ttk.Separator(scrollable_frame).pack(fill='x', pady=10)
        
        # GCSE subjects section
        ttk.Label(
            scrollable_frame, 
            text="GCSE Subjects", 
            font=('Arial', 12, 'bold')
        ).pack(anchor='w')
        
        for subject, grade in zip(student.gcse_subjects, student.gcse_grades):
            if subject:
                ttk.Label(
                    scrollable_frame, 
                    text=f"- {subject}: {grade}",
                    font=('Arial', 10)
                ).pack(anchor='w', padx=20)
        
        # Only show activities if they exist
        if student.extracurriculars or student.supercurriculars:
            ttk.Separator(scrollable_frame).pack(fill='x', pady=10)
            
            # Extracurriculars
            if student.extracurriculars:
                ttk.Label(
                    scrollable_frame, 
                    text="Extracurricular Activities", 
                    font=('Arial', 12, 'bold')
                ).pack(anchor='w')
                
                for activity in student.extracurriculars:
                    ttk.Label(
                        scrollable_frame, 
                        text=f"- {activity}",
                        font=('Arial', 10)
                    ).pack(anchor='w', padx=20)
            
            # Supercurriculars
            if student.supercurriculars:
                ttk.Label(
                    scrollable_frame, 
                    text="Supercurricular Activities", 
                    font=('Arial', 12, 'bold')
                ).pack(anchor='w', pady=(10, 0))
                
                for activity in student.supercurriculars:
                    ttk.Label(
                        scrollable_frame, 
                        text=f"- {activity}",
                        font=('Arial', 10)
                    ).pack(anchor='w', padx=20)
        
        # Separator
        ttk.Separator(scrollable_frame).pack(fill='x', pady=10)
        
        # Admission Analysis section
        ttk.Label(
            scrollable_frame, 
            text="Admission Analysis", 
            font=('Arial', 12, 'bold')
        ).pack(anchor='w')
        
        # Create a frame for the analysis text
        analysis_frame = ttk.Frame(scrollable_frame)
        analysis_frame.pack(fill='x', padx=10, pady=5)
        
        # Display the analysis content
        analysis_text = tk.Text(
            analysis_frame, 
            wrap='word', 
            height=10, 
            font=('Arial', 10),
            padx=5,
            pady=5
        )
        analysis_text.pack(fill='both', expand=True)
        
        # Insert all analysis reports
        for uni_type, content in report.items():
            analysis_text.insert('end', f"{uni_type.capitalize()}:\n", 'bold')
            analysis_text.insert('end', f"{content}\n\n")
            analysis_text.tag_configure('bold', font=('Arial', 10, 'bold'))
        
        analysis_text.config(state='disabled')
        
        # Close button
        ttk.Button(
            scrollable_frame, 
            text="Close", 
            command=report_win.destroy
        ).pack(pady=10)

# Apprenticeship Application Classes
class Student_Profile:
    def __init__(self, apprenticeships, subjects, grades, status, gcse_subjects=None, gcse_grades=None, extracurriculars=None, supercurriculars=None):
        self.apprenticeships = apprenticeships
        self.subjects = subjects
        self.grades = grades
        self.status = status
        self.gcse_subjects = gcse_subjects if gcse_subjects else []
        self.gcse_grades = gcse_grades if gcse_grades else []
        self.extracurriculars = extracurriculars if extracurriculars else []
        self.supercurriculars = supercurriculars if supercurriculars else []

    def calculate_gcse_score(self):
        """Convert GCSE grades to numerical values for analysis"""
        grade_points = {'9':9, '8':8, '7':7, '6':6, '5':5, '4':4, 
                       '3':3, '2':2, '1':1, 'U':0}
        return sum(grade_points.get(grade, 0) for grade in self.gcse_grades)
    
    def get_profile_dict(self):
        """Convert profile to dictionary for saving/analysis"""
        return {
            'apprenticeships': self.apprenticeships,
            'subjects': self.subjects,
            'grades': self.grades,
            'status': "Current Applicant",
            'gcse_subjects': self.gcse_subjects,
            'gcse_grades': self.gcse_grades,
            'extracurriculars': self.extracurriculars,
            'supercurriculars': self.supercurriculars
        }

class Data_Manager:
    def __init__(self):
        self.students = []
        self.data_loaded = False

    def load_data(self, filename):
        try:
            with open(filename, 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    student = Student_Profile(
                        row['apprenticeships'].split(','),
                        row['subjects'].split(','),
                        row['grades'].split(','),
                        row['status'],
                        row.get('gcse_subjects', '').split(','),
                        row.get('gcse_grades', '').split(','),
                        row.get('extracurriculars', '').split(','),
                        row.get('supercurriculars', '').split(',')
                    )
                    self.students.append(student)
            self.data_loaded = True
            return True
        except FileNotFoundError:
            self.data_loaded = False
            return False

    def save_student(self, filename, student):
        file_exists = os.path.isfile(filename)
        with open(filename, 'a', newline='') as file:
            fieldnames = ['apprenticeships', 'subjects', 'grades', 
                        'status', 'gcse_subjects', 'gcse_grades', 
                        'extracurriculars', 'supercurriculars']
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow({
                'apprenticeships': ','.join(student.apprenticeships),
                'subjects': ','.join(student.subjects),
                'grades': ','.join(student.grades),
                'status': student.status,
                'gcse_subjects': ','.join(student.gcse_subjects),
                'gcse_grades': ','.join(student.gcse_grades),
                'extracurriculars': ','.join(student.extracurriculars),
                'supercurriculars': ','.join(student.supercurriculars)
            })

class Validation_Helper:
    def __init__(self, analyser):
        self.analyser = analyser

    def validate_apprenticeships(self, selected_apps):
        if not selected_apps:
            return (False, "Please select at least one degree apprenticeship")
        return (True, "")

    def validate_grades(self, subjects, grades, a_level_grades, btec_grades):
        # Check first 3 subjects are mandatory
        if len([sub for sub in subjects[:3] if sub]) < 3:
            return (False, "First 3 A-Level subjects are mandatory!")
        
        # Check first 3 grades are mandatory
        if len([grade for grade in grades[:3] if grade]) < 3:
            return (False, "First 3 A-Level grades are mandatory!")
        
        # Validate grade types match subject types
        for i, (subject, grade) in enumerate(zip(subjects, grades)):
            if subject and grade:
                is_btec = "BTEC" in subject
                if is_btec and grade not in btec_grades:
                    return (False, 
                        f"BTEC subjects must use BTEC grades\nError in row {i+1}: {subject} - {grade}")
                elif not is_btec and grade not in a_level_grades:
                    return (False, 
                        f"A-Level subjects must use A-Level grades\nError in row {i+1}: {subject} - {grade}")
        return (True, "")

    def validate_gcse(self, gcse_subjects, gcse_grades):
        mandatory_subjects = ["Maths", "English Language", "English Literature"]
        entered_subjects = gcse_subjects[:3]
        
        # Check if all mandatory subjects are present
        missing_mandatory = []
        for i, subject in enumerate(mandatory_subjects):
            if entered_subjects[i] != subject:
                missing_mandatory.append(subject)
        
        if missing_mandatory:
            return (False, 
                f"Mandatory GCSE subjects missing: {', '.join(missing_mandatory)}")
        
        # Check first 3 grades are entered
        if len([grade for grade in gcse_grades[:3] if grade]) < 3:
            return (False, "First 3 GCSE grades are mandatory!")
            
        return (True, "")

class Report_Generator:
    def __init__(self, analyser):
        self.analyser = analyser

    def generate_student_report(self, student_profile, students):
        report = {
            'apprenticeships': self._generate_apprenticeship_report(student_profile.apprenticeships, students),
            'other': self._generate_other_apps_report(student_profile, students)
        }
        return report

    def _generate_apprenticeship_report(self, apprenticeships, students):
        report_lines = []
        
        for app in apprenticeships:
            app_students = [s for s in students if app in s.apprenticeships]
            if not app_students:
                report_lines.append(f"No historical data found for {app}")
                continue
            
            success_rate = sum(1 for s in app_students if s.status == "Accepted") / len(app_students)
            report_lines.extend([
                f"Apprenticeship: {app}",
                f"Historical Acceptance Rate: {success_rate:.1%}",
                "--------------------------------------------------",
                "Successful applicants typically had:"
            ])
            
            # Add grade analysis
            avg_grades = self._calculate_avg_grades(app_students)
            report_lines.append(f"- A-Level grades: {avg_grades}")
            
            # Add GCSE analysis if available
            if any(s.gcse_grades for s in app_students):
                avg_gcse = self._calculate_avg_gcse(app_students)
                report_lines.append(f"- GCSE average score: {avg_gcse:.1f}")
            
            report_lines.append("\n")
        
        return '\n'.join(report_lines)

    def _generate_other_apps_report(self, student_profile, students):
        selected_apps = student_profile.apprenticeships
        other_students = [
            s for s in students 
            if any(app in s.apprenticeships for app in selected_apps)
        ]
        
        if not other_students:
            return "No comparable data for other selected apprenticeships"
        
        report = ["Other Apprenticeship Choices Analysis:", "-------------------------------"]
        for app in student_profile.apprenticeships:
            app_students = [s for s in other_students if app in s.apprenticeships]
            if app_students:
                success_rate = sum(1 for s in app_students if s.status == "Accepted") / len(app_students)
                report.append(f"{app}: {success_rate:.1%} acceptance rate")
        
        return '\n'.join(report)

    def _calculate_avg_grades(self, students):
        grade_points = {'A*':6, 'A':5, 'B':4, 'C':3, 'D':2, 'E':1, 'U':0,
                       'Distinction*':6, 'Distinction':5, 'Merit':4, 'Pass':3}
        total = 0
        count = 0
        for student in students:
            for grade in student.grades:
                if grade in grade_points:
                    total += grade_points[grade]
                    count += 1
        return f"{total/count:.1f} average points" if count > 0 else "No grade data"

    def _calculate_avg_gcse(self, students):
        grade_points = {'9':9, '8':8, '7':7, '6':6, '5':5, '4':4, 
                       '3':3, '2':2, '1':1, 'U':0}
        total = 0
        count = 0
        for student in students:
            for grade in student.gcse_grades:
                if grade in grade_points:
                    total += grade_points[grade]
                    count += 1
        return total/count if count > 0 else 0

class Apprenticeship_Analyser:
    def __init__(self):
        self.data_manager = Data_Manager()
        self.validation = Validation_Helper(self)
        self.report_generator = Report_Generator(self)
        self.all_subjects = [
            "Art", "Biology", "Business", "BTEC ICT Level 3", "BTEC Sport Level 3", 
            "BTEC Music Level 3", "Chemistry", "Computer Science", "English Language", 
            "English Literature", "Extended Project Qualification", "Film Studies", 
            "Geography", "History", "Mathematics", "Core Mathematics", "Further Mathematics", 
            "Media Studies", "Physics", "Politics", "Psychology", "Religious Education", 
            "Sociology", "Spanish",
        ]
        self.gcse_subjects = [
            "Maths", "English Language", "English Literature", "Science", 
            "History", "Geography", "French", "Spanish", "German", "Computer Science",
            "Religious Studies", "Art", "Drama", "Music", "Physical Education",
            "Business Studies", "Statistics", "Additional Science"
        ]
        self.extracurricular_options = [
            "Sports", "Music", "Drama", "Debating", "Volunteering",
            "Student Council", "Duke of Edinburgh", "Part-time Job",
            "School Prefect", "Mentoring", "None"
        ]
        self.supercurricular_options = [
            "Subject Olympiads", "University Summer Schools", "MOOCs",
            "Subject-related Competitions", "Academic Clubs", "Research Projects",
            "Subject-related Reading", "None"
        ]
        self.a_level_grades = ["A*", "A", "B", "C", "D", "E", "U"]
        self.btec_grades = ["Distinction*", "Distinction", "Merit", "Pass", "U"]
        self.gcse_grades = ["9", "8", "7", "6", "5", "4", "3", "2", "1", "U"]
        self.apprenticeship_options = [
            "Software Engineer",
            "Data Scientist",
            "Cyber Security",
            "Digital Marketing",
            "Aerospace Engineer",
            "Civil Engineer",
            "Electrical Engineer",
            "Mechanical Engineer",
            "Accountancy",
            "Business Management",
            "Nursing",
            "Healthcare Science",
            "Law",
            "Financial Services",
            "Construction Management"
        ]
    
    @property
    def students(self):
        return self.data_manager.students
    
    def load_data(self, filename):
        return self.data_manager.load_data(filename)

class ApprenticeshipApplication(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Degree Apprenticeship Application Assistant")
        self.geometry("800x600")
        self.analyser = Apprenticeship_Analyser()
        self.current_step = 1
        self.selected_apprenticeships = tk.StringVar()
        self.create_widgets()
        self.load_data()
        
    def load_data(self):
        if not self.analyser.load_data("apprenticeship_data.csv"):
            messagebox.showwarning("Data Error", "Historical data not found! Some features may be limited.")
            
    def create_widgets(self):
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        self.app_frame = ttk.Frame(self.main_frame)
        self.grades_frame = ttk.Frame(self.main_frame)
        self.gcse_frame = ttk.Frame(self.main_frame)
        self.activities_frame = ttk.Frame(self.main_frame)
        
        self.create_apprenticeship_step()
        self.create_grades_step()
        self.create_gcse_step()
        self.create_activities_step()
        self.show_current_step()
        
    def show_current_step(self):
        frames = [self.app_frame, self.grades_frame, 
                 self.gcse_frame, self.activities_frame]
        for i, frame in enumerate(frames):
            frame.pack() if i == self.current_step - 1 else frame.pack_forget()

    def create_apprenticeship_step(self):
        ttk.Label(self.app_frame, text="Step 1: Select Degree Apprenticeships", font=('Arial', 14)).pack(pady=10)
    
        ttk.Label(self.app_frame, text="Choose your preferred degree apprenticeships:").pack(pady=5)
        
        self.app_listbox = tk.Listbox(
            self.app_frame, 
            selectmode=tk.MULTIPLE,
            height=10,
            width=50,
            font=('Arial', 10)
        )
        
        for app in self.analyser.apprenticeship_options:
            self.app_listbox.insert(tk.END, app)
            
        scrollbar = ttk.Scrollbar(self.app_frame, orient="vertical")
        scrollbar.config(command=self.app_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.app_listbox.config(yscrollcommand=scrollbar.set)
        
        self.app_listbox.pack(pady=10)
        
        ttk.Button(self.app_frame, text="Next →", command=self.next_step).pack(pady=20)

    def auto_complete(self, event, combo, options_list):
        value = event.widget.get()
        combo['values'] = [item for item in options_list if value.lower() in item.lower()]
        combo.event_generate('<Down>')
        return "break"

    def create_grades_step(self):
        self.subject_vars = [tk.StringVar() for _ in range(5)]
        self.grade_vars = [tk.StringVar() for _ in range(5)]
        
        ttk.Label(self.grades_frame, text="Step 2: A-Level Subjects & Grades", font=('Arial', 14)).pack(pady=10)
        
        for i in range(5):
            frame = ttk.Frame(self.grades_frame)
            frame.pack(pady=5)
            
            sub_combo = ttk.Combobox(frame, values=self.analyser.all_subjects, 
                                   textvariable=self.subject_vars[i], width=30)
            sub_combo.pack(side=tk.LEFT, padx=5)
            sub_combo.bind("<KeyRelease>", lambda event, cb=sub_combo: self.auto_complete(event, cb, self.analyser.all_subjects))
            
            grade_combo = ttk.Combobox(frame, values=self.analyser.a_level_grades + self.analyser.btec_grades, 
                                     textvariable=self.grade_vars[i], width=10)
            grade_combo.pack(side=tk.LEFT)
            grade_combo.bind("<KeyRelease>", lambda event, cb=grade_combo: self.auto_complete(event, cb, self.analyser.a_level_grades + self.analyser.btec_grades))
            
            if i < 3:
                ttk.Label(frame, text="*", foreground="red").pack(side=tk.LEFT)
                
        ttk.Button(self.grades_frame, text="← Back", command=self.prev_step).pack(side=tk.LEFT, padx=10)
        ttk.Button(self.grades_frame, text="Next →", command=self.next_step).pack(side=tk.RIGHT, padx=10)

    def create_gcse_step(self):
        self.gcse_subject_vars = [tk.StringVar() for _ in range(13)]
        self.gcse_grade_vars = [tk.StringVar() for _ in range(13)]
        
        # Set default values for first 3 subjects
        self.gcse_subject_vars[0].set("Maths")
        self.gcse_subject_vars[1].set("English Language")
        self.gcse_subject_vars[2].set("English Literature")
        
        ttk.Label(self.gcse_frame, text="Step 3: GCSE Subjects & Grades", font=('Arial', 14)).pack(pady=10)
        
        for i in range(13):
            frame = ttk.Frame(self.gcse_frame)
            frame.pack(pady=5)
            
            sub_combo = ttk.Combobox(frame, values=self.analyser.gcse_subjects, 
                                textvariable=self.gcse_subject_vars[i], width=25)
            sub_combo.pack(side=tk.LEFT, padx=5)
            sub_combo.bind("<KeyRelease>", lambda event, cb=sub_combo: self.auto_complete(event, cb, self.analyser.gcse_subjects))
            
            grade_combo = ttk.Combobox(frame, values=self.analyser.gcse_grades, 
                                    textvariable=self.gcse_grade_vars[i], width=5)
            grade_combo.pack(side=tk.LEFT)
            grade_combo.bind("<KeyRelease>", lambda event, cb=grade_combo: self.auto_complete(event, cb, self.analyser.gcse_grades))
            
            if i < 3:
                ttk.Label(frame, text="*", foreground="red").pack(side=tk.LEFT)
        
        ttk.Button(self.gcse_frame, text="← Back", command=self.prev_step).pack(side=tk.LEFT, padx=10)
        ttk.Button(self.gcse_frame, text="Next →", command=self.next_step).pack(side=tk.RIGHT, padx=10)

    def create_activities_step(self):
        ttk.Label(self.activities_frame, text="Step 4: Extracurriculars & Supercurriculars (Optional)", 
                font=('Arial', 14)).pack(pady=10)
        
        # Extracurriculars section
        extracurricular_frame = ttk.Frame(self.activities_frame)
        extracurricular_frame.pack(pady=10)
        ttk.Label(extracurricular_frame, text="Extracurricular Activities:", 
                font=('Arial', 10, 'bold')).pack()
        
        self.extracurricular_vars = [tk.StringVar(value="None") for _ in range(3)]
        for i in range(3):
            frame = ttk.Frame(extracurricular_frame)
            frame.pack(pady=5)
            ttk.Label(frame, text=f"Activity {i+1}:").pack(side=tk.LEFT)
            combo = ttk.Combobox(frame, values=self.analyser.extracurricular_options, 
                            textvariable=self.extracurricular_vars[i], width=30)
            combo.pack(side=tk.LEFT, padx=5)
            combo.bind("<KeyRelease>", lambda event, cb=combo: self.auto_complete(event, cb, self.analyser.extracurricular_options))
            
        # Supercurriculars section 
        supercurricular_frame = ttk.Frame(self.activities_frame)
        supercurricular_frame.pack(pady=10)
        ttk.Label(supercurricular_frame, text="Supercurricular Activities:", 
                font=('Arial', 10, 'bold')).pack()
        
        self.supercurricular_vars = [tk.StringVar(value="None") for _ in range(3)]
        for i in range(3):
            frame = ttk.Frame(supercurricular_frame)
            frame.pack(pady=5)
            ttk.Label(frame, text=f"Activity {i+1}:").pack(side=tk.LEFT)
            combo = ttk.Combobox(frame, values=self.analyser.supercurricular_options, 
                            textvariable=self.supercurricular_vars[i], width=30)
            combo.pack(side=tk.LEFT, padx=5)
            combo.bind("<KeyRelease>", lambda event, cb=combo: self.auto_complete(event, cb, self.analyser.supercurricular_options))
            
        # Buttons
        button_frame = ttk.Frame(self.activities_frame)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="← Back", command=self.prev_step).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Generate Report", command=self.generate_report).pack(side=tk.RIGHT, padx=10)

    def next_step(self):
        if self.current_step == 1:
            selected = [self.app_listbox.get(i) for i in self.app_listbox.curselection()]
            valid, msg = self.analyser.validation.validate_apprenticeships(selected)
            if not valid:
                messagebox.showerror("Error", msg)
                return
            self.current_step = 2
            
        elif self.current_step == 2:
            valid, msg = self.analyser.validation.validate_grades(
                [var.get() for var in self.subject_vars],
                [var.get() for var in self.grade_vars],
                self.analyser.a_level_grades,
                self.analyser.btec_grades
            )
            if not valid:
                messagebox.showerror("Error", msg)
                return
            self.current_step = 3
            
        elif self.current_step == 3:
            valid, msg = self.analyser.validation.validate_gcse(
                [var.get() for var in self.gcse_subject_vars],
                [var.get() for var in self.gcse_grade_vars]
            )
            if not valid:
                messagebox.showerror("Error", msg)
                return
            self.current_step = 4
            
        self.show_current_step()

    def prev_step(self):
        self.current_step = max(1, self.current_step - 1)
        self.show_current_step()

    def generate_report(self):
        # Create student profile
        selected_apps = [self.app_listbox.get(i) for i in self.app_listbox.curselection()]
        student = Student_Profile(
            apprenticeships=selected_apps,
            subjects=[var.get() for var in self.subject_vars if var.get()],
            grades=[var.get() for var in self.grade_vars if var.get()],
            status="Current Applicant",
            gcse_subjects=[var.get() for var in self.gcse_subject_vars if var.get()],
            gcse_grades=[var.get() for var in self.gcse_grade_vars if var.get()],
            extracurriculars=[var.get() for var in self.extracurricular_vars 
                            if var.get() and var.get() != "None"],
            supercurriculars=[var.get() for var in self.supercurricular_vars 
                            if var.get() and var.get() != "None"]
        )
        
        # Ask user if they want to save their data
        save_data = messagebox.askyesno(
            "Save Data", 
            "Would you like to save your data to the database for future reference?"
        )
        
        if save_data:
            # Save the student data
            self.analyser.data_manager.save_student("apprenticeship_data.csv", student)
            messagebox.showinfo("Success", "Your data has been saved successfully!")
        
        # Generate report
        report = self.analyser.report_generator.generate_student_report(
            student, 
            self.analyser.students
        )
        
        # Display report in the new format
        report_win = tk.Toplevel()
        report_win.title("Degree Apprenticeship Application Report")
        report_win.geometry("800x700")
        
        # Main container frame with scrollbar
        main_frame = ttk.Frame(report_win)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Header
        ttk.Label(
            scrollable_frame, 
            text="Degree Apprenticeship Application Report", 
            font=('Arial', 16, 'bold')
        ).pack(pady=(10, 5), anchor='w')
        
        # Apprenticeship choices section
        ttk.Label(
            scrollable_frame, 
            text="Selected Apprenticeships", 
            font=('Arial', 12, 'bold')
        ).pack(pady=(5, 0), anchor='w')
        
        for app in student.apprenticeships:
            ttk.Label(
                scrollable_frame, 
                text=f"- {app}",
                font=('Arial', 10)
            ).pack(anchor='w', padx=20)
        
        # Separator
        ttk.Separator(scrollable_frame).pack(fill='x', pady=10)
        
        # A-Level subjects section
        ttk.Label(
            scrollable_frame, 
            text="A-Level Subjects", 
            font=('Arial', 12, 'bold')
        ).pack(anchor='w')
        
        for subject, grade in zip(student.subjects, student.grades):
            if subject:
                ttk.Label(
                    scrollable_frame, 
                    text=f"- {subject}: {grade}",
                    font=('Arial', 10)
                ).pack(anchor='w', padx=20)
        
        # Separator
        ttk.Separator(scrollable_frame).pack(fill='x', pady=10)
        
        # GCSE subjects section
        ttk.Label(
            scrollable_frame, 
            text="GCSE Subjects", 
            font=('Arial', 12, 'bold')
        ).pack(anchor='w')
        
        for subject, grade in zip(student.gcse_subjects, student.gcse_grades):
            if subject:
                ttk.Label(
                    scrollable_frame, 
                    text=f"- {subject}: {grade}",
                    font=('Arial', 10)
                ).pack(anchor='w', padx=20)
        
        # Only show activities if they exist
        if student.extracurriculars or student.supercurriculars:
            ttk.Separator(scrollable_frame).pack(fill='x', pady=10)
            
            # Extracurriculars
            if student.extracurriculars:
                ttk.Label(
                    scrollable_frame, 
                    text="Extracurricular Activities", 
                    font=('Arial', 12, 'bold')
                ).pack(anchor='w')
                
                for activity in student.extracurriculars:
                    ttk.Label(
                        scrollable_frame, 
                        text=f"- {activity}",
                        font=('Arial', 10)
                    ).pack(anchor='w', padx=20)
            
            # Supercurriculars
            if student.supercurriculars:
                ttk.Label(
                    scrollable_frame, 
                    text="Supercurricular Activities", 
                    font=('Arial', 12, 'bold')
                ).pack(anchor='w', pady=(10, 0))
                
                for activity in student.supercurriculars:
                    ttk.Label(
                        scrollable_frame, 
                        text=f"- {activity}",
                        font=('Arial', 10)
                    ).pack(anchor='w', padx=20)
        
        # Separator
        ttk.Separator(scrollable_frame).pack(fill='x', pady=10)
        
        # Admission Analysis section
        ttk.Label(
            scrollable_frame, 
            text="Admission Analysis", 
            font=('Arial', 12, 'bold')
        ).pack(anchor='w')
        
        # Create a frame for the analysis text
        analysis_frame = ttk.Frame(scrollable_frame)
        analysis_frame.pack(fill='x', padx=10, pady=5)
        
        # Display the analysis content
        analysis_text = tk.Text(
            analysis_frame, 
            wrap='word', 
            height=10, 
            font=('Arial', 10),
            padx=5,
            pady=5
        )
        analysis_text.pack(fill='both', expand=True)
        
        # Insert all analysis reports
        for app_type, content in report.items():
            analysis_text.insert('end', f"{app_type.capitalize()}:\n", 'bold')
            analysis_text.insert('end', f"{content}\n\n")
            analysis_text.tag_configure('bold', font=('Arial', 10, 'bold'))
        
        analysis_text.config(state='disabled')
        
        # Close button
        ttk.Button(
            scrollable_frame, 
            text="Close", 
            command=report_win.destroy
        ).pack(pady=10)

if __name__ == "__main__":
    WelcomeScreen()