import sqlite3
import hashlib
import os
import re
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


# ==================== University Application Classes ====================

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


# ==================== Apprenticeship Application Classes ====================

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
