import csv, datetime, os, hashlib, binascii

menu_options = "Please choose one of the following options by typing it:\n- Login\n- Register\n- Exit"

class Patient:
    def __init__(self):
        """The patient contructor which initialises the date of registration and the login attempts for each new
        user."""
        self.registered_on = datetime.datetime.now()
        self.login_attempts = 3

    def save_patient(self, registered_email, registered_password):
        """Saves patient details in the .csv file using the initial variables from the constructor in the Patient()
        class and the password and emailed later supplier by the register function in the Register() class."""
        with open("patients.csv", "a", newline="") as patient_file:
            writer = csv.writer(patient_file, delimiter=",")
            writer.writerow(
                [
                    registered_email,
                    self.password_hash(registered_password),
                    self.registered_on,
                    self.login_attempts,
                ]
            )

    def password_hash(self, registered_password):
        """Hashes the user's password by producing a salt and hashing it using the SHA-256 cryptographic hash function then
        incoding it to 8 bits. The salt is added to password and hashed with SHA-256 hash function by iterating the
        whole process 100000 times."""
        salt = hashlib.sha256(os.urandom(32)).hexdigest().encode("ascii")
        hashed_password = hashlib.pbkdf2_hmac("sha256", registered_password.encode("utf-8"), salt, 100000)
        hashed_password = binascii.hexlify(hashed_password)  # converts from binary data to hexadecimal
        hashed_password = (salt + hashed_password).decode("ascii")
        return hashed_password
        
class Register:
    def __init__(self):
        """Definining a constructor which initialises the user email."""
        self.email = input("Please enter your email address: ").lower()

    def register(self):
        """Registers a new user if the user doesn't exist, checks if the user's password meets the criteria, whether the
        two passwords entered match and then stores the user's details in the csv file."""
        self.valid_email()
        if self.email != patient_search(self.email)[0]:
            password = input("Please enter your password: ")
            password = self.check_pw_suitability(password)
            password_again = input("Please confirm your password: ")
            password = self.double_pw_check(password, password_again)
            p = Patient()
            p.save_patient(self.email, password)
            print("You have registered successfully!\n")
            print(menu_options)
            login_page()
        else:
            print("Account already exists, please log in instead.")
            l = Login()
            l.login()

    def pw_composition_check(self, provided_password):
        """Confirms whether the user's password has any special characters, numbers, capital letters or white
        spaces."""
        special_characters = "!#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
        upper_count = 0
        number_count = 0
        special_characters_count = 0
        space_count = 0
        for char in provided_password:
            if char.isupper():
                upper_count = upper_count + 1
            elif char in special_characters:
                special_characters_count = special_characters_count + 1
            elif char.isnumeric():
                number_count = number_count + 1
            elif char is " ":
                space_count = space_count + 1
        return upper_count, number_count, special_characters_count, space_count  #

    def check_pw_suitability(self, provided_password):
        """Applies the pw_composition_check function to verify whether the password meets the requirements."""
        composition_check = self.pw_composition_check(provided_password)
        if (
            len(provided_password) <= 8
            or len(provided_password) > 64
            or composition_check[0] == 0
            or composition_check[1] == 0
            or composition_check[2] == 0
            or composition_check[3] == 0
        ):
            print("Password must contain at least one whitespace, number and upper-case letter, it must be between 8 and 64 characters long and it must include at least one of the following special characters: !#$%&'()*+,-./:;<=>?@[\]^_`{|}~")
            provided_password = input("Please enter your password: ")
            return self.check_pw_suitability(provided_password)
        else:
            return provided_password

    def double_pw_check(self, pw1, pw2):
        """Checks whether the two passwords entered match."""
        if pw1 == pw2:
            return pw1
        else:
            print("The passwords provided do not match.")
            pw1 = input("Please enter your password: ")
            pw1 = self.check_pw_suitability(pw1)
            pw2 = input("Please confirm your password: ")
            return self.double_pw_check(pw1, pw2)
        
    def check_email(self):
        at_sign_count = 0
        whitespace_count = 0
        dot_count = 0
        for char in self.email:
            if char == "@":
                at_sign_count = at_sign_count + 1
            elif char == " ":
                whitespace_count = whitespace_count + 1
            elif char == ".":
                dot_count = dot_count + 1
        return at_sign_count, whitespace_count, dot_count
                
    def valid_email(self):
        email_composition=self.check_email()
        if email_composition[0] == 1 and email_composition[1] == 0 and email_composition[2] >= 1:
            return self.email
        else:
            print ("The email address is invalid")
            self.email = input("Please enter your email address: ").lower()
            self.valid_email()

class Login:
    def __init__(self):
        """Defines a constructor and initialises the user email."""
        self.email = input("Please enter your email address: ").lower()

    def login(self):
        """Used for patient login only; 3 login attempts allowed, account locked after."""
        login_attempts = patient_search(self.email)[3]
        if int(login_attempts) == 0:
            print("Account is locked, please contact reception.")
        elif (int(login_attempts) == -1):  # checks for patients who are not yet registered
            password = input("Please enter your password: ")
            print("Login details are incorrect")
            self.email = input("Please enter your email address or type 'menu' to return to main menu: ").lower()
            if self.email == 'menu':
                print(menu_options)
                login_page()
            else:
                self.login()
        elif int(login_attempts) > 0:
            self.unlocked_user_login(login_attempts)

    def unlocked_user_login(self, login_attempts):
        """Processes patient's login of the patients who are registered and are not locked out. Used by the main
        login() function."""
        password = input("Please enter your password: ")
        if self.verify_password(password) == True:
            print("You have logged in successully.")
            exit()
        else:
            login_attempts = int(login_attempts) - 1
            self.update_login_attempts(login_attempts)
            if login_attempts > 0:
                print(
                    "Login unsuccessful. You have",
                    login_attempts,
                    "attempt(s) remaining",
                )
                self.login()
            else:
                print("Account is locked, please contact reception.")
                exit()

    def verify_password(self, provided_password):
        """Verifies the password entered during the login: hashedt he password entered and compares it against the
        hashed password stored in the csv file."""
        with open("patients.csv", "r") as patient_file:
            reader = csv.reader(patient_file, delimiter=",")
            next(reader)
            for row in reader:
                if row[0] == self.email:
                    stored_password = row[1]
                    salt = stored_password[:64]
                    pwdhash = hashlib.pbkdf2_hmac("sha256", provided_password.encode("utf-8"), salt.encode("ascii"), 100000)
                    stored_password = stored_password[64:]
                    pwdhash = binascii.hexlify(pwdhash).decode("ascii")
                    if pwdhash == stored_password:
                        return True
                    else:
                        return False
                    # Do I need another else here???

    def update_login_attempts(self, attempts):
        """Locks the user account by updating the locked entry for the user to 1, writing the
        updated entry into the new file in addition to all other entries, renaming the new
        file to the users.csv and deleting the old patients.csv file."""
        with open("patients.csv", "r") as in_file:
            reader = csv.reader(in_file, delimiter=",")
            next(reader)
            with open("locked_patients.csv", "w", newline="") as out_file:
                writer = csv.writer(out_file)
                writer.writerow(["email", "password", "registered_on", "login_attempts"])
                for row in reader:
                    if row[0] == self.email:
                        row1 = row
                        row1[3] = str(attempts)
                    writer.writerow(row)
        os.rename("patients.csv", "old_patients.csv")
        os.rename("locked_patients.csv", "patients.csv")
        os.remove("old_patients.csv")

def read_file():
    with open("patients.csv", "r") as in_file:
        reader = csv.reader(in_file, delimiter=",")
        return reader

def patient_search(entered_email):
    """A function used by both Register() and Login() classes to confirm the patient's presence in the
    .csv file"""
    with open("patients.csv", "r") as patient_file:
        reader = csv.reader(patient_file, delimiter=",")
        next(reader)
        for row in reader:
            if row[0] == entered_email:
                return row
        return -1, -1, -1, -1

def create_patient_file():
    """Creates the initial user file."""
    with open("patients.csv", "a", newline="") as patient_file:
        if os.stat("patients.csv").st_size == 0:
            writer = csv.writer(patient_file, delimiter=",")
            writer.writerow(["email", "password", "registered_on", "login_attempts"])

def login_page():
    """Load the user interface where register, login and exist choice can be made."""
    option = input(">> ")
    if option.lower() == "register":
        r = Register()
        r.register()
    elif option.lower() == "login":
        l = Login()
        l.login()
    elif option.lower() == "exit":
        print("ASMIS is shutting down...")
        exit()
    else:
        print("Please type a valid option.")
        login_page()

print(menu_options)
create_patient_file() # ensures file exists in case user tries to log in first
login_page()
