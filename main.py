import logging
import re
import operator
logging.basicConfig(filename='log.log',level=logging.DEBUG, format='%(asctime)s %(message)s')

logging.info('It works')

print("\t**********************************************")
print("\t***  Greeter - Hello old and new friends!  ***")
print("\t**********************************************")

class FileManager: 
    @staticmethod
    def lock_file():
        file = open("save.json", "r")
        data = file.readlines()
        file = open("save.json", "w")
        for line in data:
            file.write(FileManager.ceasar_cipher(line, 12))
        file.close()

    @staticmethod
    def unlock_file():
        file = open("save.json", "r")
        data = file.readlines()
        file = open("save.json", "w")
        for line in data:
            file.write(FileManager.ceasar_cipher(line, -12))
        file.close()

    @staticmethod
    def ceasar_cipher(input, shift):
        lower = "abcdefghijklmnopqrstuvwxyz"
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        chars = "~!@\"#$%^&*_-+=`|\\(){}[]:;'<>,.?/"
        allowed_chars = lower+upper+digits+chars

        cipher = ""
        for c in input:
            print("char: '"+c+"'\n")
            if c == ' ' or c == '\n' or c == '\t' or c == "\r":
                cipher = cipher + c
            else: 
               i = allowed_chars.index(c)
               cipher = cipher + allowed_chars[(i + shift) % len(allowed_chars)]
        return cipher



notLoggedIn = True

# 0 = notLoggedIn, 1 = super admininstrator, 2 = system administrator, 3 = advisor, 4 = blocked
userlevel = 0



while notLoggedIn:
    tries = 0
    if tries == 3:
        userlevel = 4
        print("Blocked out")

    username = input("Fill in username: ")
    password = input("Fill in password: ")

    if username == "admin" and password == "geheim":
        print("Succesvol ingelogd")
        userlevel = 1
        notLoggedIn = False
        #FileManager.unlock_file()
    else:
        print("Verkeerde username en/of wachtwoord")
        tries + 1
        #FileManager.lock_file()




# all these validations: 
# Client should have the following data:
# - Full Name
# - Addres 
#   - Street + House Number
#   - Zip Code (DDDDXX)
#   - City (should match a city in a list of 10 city names)
# - Email Adress
# - Mobile Phone (+31-6-DDDD-DDDD)

class Client:
    def __init__(self, userLevel, full_name, address, email, phone):
        self.userLevel = userLevel
        self.full_name = full_name
        self.address = address
        self.email = email
        self.phone = phone

    mailpattern = "[a-zA-Z0-9\\+\\.\\_\\%\\-\\+]{1,256}\\@[a-zA-Z0-9][a-zA-Z0-9\\-]{0,64}(\\.[a-zA-Z0-9][a-zA-Z0-9\\-]{0,25})+"

    email = property(operator.attrgetter('_email'))

    @email.setter
    def email(self, d):
        if not re.match(self.mailpattern, d):
            print("mailadres not valid!")

class Address:
    def __init__(self, street, houseNumber, zip, city):
        self.street = street
        self.houseNumber = houseNumber
        self.zip = zip
        self.city = city

cleint = Client(0, "nee denk ik", Address("hallostraat", 36, "1234ab", "Winterfell"), "apenstaartje@gmailpuntcom.com.", "+31-6-50601804")




# password:
# length: 8..30
# abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789 ~!@#$%^&*_-+=`|\(){}[]:;'<>,.?/


def validate_password(input):
    lower = "abcdefghijklmnopqrstuvwxyz"
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    chars = "~!@#$%^&*_-+=`|\\(){}[]:;'<>,.?/"
    allowed_chars = lower+upper+digits+chars

    if len(input) not in range(8, 31):
        return False

    for char in input:
        if char not in allowed_chars:
            return False
    return True

def validate_username(input):
    lower = "abcdefghijklmnopqrstuvwxyz"
    digits = "0123456789"
    chars = "_-'."
    allowed_chars = lower+digits+chars

    if len(input) not in range(5, 21):
        return False

    for char in input:
        if char not in allowed_chars:
            return False
    return True




# TODO: C1 Authentication for users are properly implemented.
# ▪ System must authenticate a user.
# ▪ Usernames and passwords can be stored in a local file, using a simple encryption method of your choice, such 
# as Caesar sipher. The only security measure on username and password file is that the file should not be readable 
# in text mode by a text editor. You do not need to implement complex mechanism, but you are free to choose 
# your own option. As long as, the file is not readable by a text editor, the criterion is assessed as satisfactory.

# TODO: C2 Users access level are implemented.
# ▪ Distinguish between different categories of users and their access level, as a result of authentication process.
# ▪ By this we mean for example, a user with advisor level should not be able to see the menu option for adding a new advisor user.

# TODO: C3 All inputs are properly validated.
# ▪ All inputs, including both use-generated (e.g. client name, email, etc.) inputs and system-generated inputs (e.g. city) must be validated.

# TODO: C4 Invalid inputs are properly handled.
# ▪ In case of invalid input by user, the system must take appropriate action. For example, it might only display a 
# proper message to the user, or might ban the user for extra attempts, depends on the number of invalid inputs for a specific field.

# TODO: C5 Suspicious activities are logged.
# ▪ In case of suspicious activities or realizing an attack; for example, a user is attacking the system by trying many 
# passwords (brute force), or an open session is used by a stranger and entering suspicious characters in irrelevant 
# fields of data (e.g. entering ‘/’ in user name multiple times); then the system need to take proper action, and log 
# the activity in a file. This file must be available only to Super Administrator or System Administrator in menu options.