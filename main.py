import logging, re, operator, json
logging.basicConfig(filename='log.log',level=logging.DEBUG, format='%(asctime)s %(message)s')

logging.info('It works')

print("\t**********************************************")
print("\t***  Greeter - Hello old and new friends!  ***")
print("\t**********************************************")

class FileManager: 
    
    @staticmethod
    def save(clientData):
        json.dump(clientData, open('save.json', 'w'), default=lambda o: o.__dict__)
        FileManager.lock_file()

    @staticmethod
    def load():
        FileManager.unlock_file()
        data = json.load(open('save.json', 'r'))

        clients = []
        for client in data:
            address = client["address"]
            clients.append(Client(
                client["userLevel"], 
                client["username"], 
                client["password"], 
                client["fullName"], 
                Address(
                    address["street"],
                    address["houseNumber"],
                    address["zipcode"],
                    address["city"]
                ),
                client["email"], 
                client["phone"]
            ))
        FileManager.lock_file()
        return clients
            
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
            if c == ' ' or c == '\n' or c == '\t' or c == "\r":
                cipher = cipher + c
            else: 
               i = allowed_chars.index(c)
               cipher = cipher + allowed_chars[(i + shift) % len(allowed_chars)]
        return cipher


class Roles:
    unauthenticated = 0
    superAdministrator = 1
    systemAdministrator = 2
    advisor = 3
    client = 4
    blocked = 5

    @staticmethod
    def allow_creating_client(client):
        return client.userLevel in [Roles.systemAdministrator]

    @staticmethod
    def allow_creating_advisor(client):
        return client.userLevel in [Roles.systemAdministrator]

    @staticmethod
    def allow_creating_system_admin(client):
        return client.userLevel in [Roles.superAdministrator]

    @staticmethod
    def allow_creating_super_admin():
        return False

class Validators:
    @staticmethod
    def isValidEmail(email):
        mailpattern = "[a-zA-Z0-9\\+\\.\\_\\%\\-\\+]{1,256}\\@[a-zA-Z0-9][a-zA-Z0-9\\-]{0,64}(\\.[a-zA-Z0-9][a-zA-Z0-9\\-]{0,25})+"
        if re.match(mailpattern, email):
            logger.info("Valid email")
            return True
        else: 
            print("Invalid email, does not match syntax")
            logger.info("Invalid email, does not match syntax")
            return False

    @staticmethod
    def isValidPhone(phone):
        phonepattern = "\+31-6-[0-9]{4}-[0-9]{4}"
        if re.match(phonepattern, phone):
            logger.info("Valid phone number")
            return True
        else: 
            print("Invalid phone number, does not match syntax")
            logger.info("Invalid phone number, does not match syntax")
            return False

    @staticmethod
    def isValidPassword(password):
        lower = "abcdefghijklmnopqrstuvwxyz"
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        chars = "~!@#$%^&*_-+=`|\\(){}[]:;'<>,.?/"
        allowed_chars = lower+upper+digits+chars

        containregexpattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]$"

        if len(value) not in range(8, 31):
            print("Invalid because password not between 8 and 30 characters")
            logger.info("Invalid because password not between 8 and 30 characters")
            return False

        if not re.match(containregexpattern, value):
            print("Invalid because password does not contain 1 uppercase, 1 lowercase, 1 digit or 1 special character")
            logger.info("Invalid because password does not contain 1 uppercase, 1 lowercase, 1 digit or 1 special character")
            return False

        for char in value:
            if char not in allowed_chars:
                print("Invalid because password contains invalid character")
                logger.info("Invalid because password contains invalid character")
                return False
        logger.info("Valid password")
        return True


    @staticmethod
    def isValidUsername(username):
        value = value.lower()

        lower = "abcdefghijklmnopqrstuvwxyz"
        digits = "0123456789"
        chars = "_-'."
        allowed_chars = lower+digits+chars

        if len(value) not in range(5, 21):
            print("Invalid because username not between 5 and 20 characters")
            logger.info("Invalid because username not between 5 and 20 characters")
            return False

        if not value[0].isalpha():
            print("Invalid because username does not start with a letter")
            logger.info("Invalid because username does not start with a letter")
            return False

        for char in value:
            if char not in allowed_chars:
                print("Invalid because username contains invalid character")
                logger.info("Invalid because username contains invalid character")
                return False
        logger.info("Valid username")
        return True
        
    @staticmethod
    def isValidClientUserLevel(userLevel):
        if userLevel in [Roles.systemAdministrator, Roles.advisor, Roles.client]:
            logger.info("Valid userlevel")
            return True
        else:
            print("Invalid userlevel for action")
            logger.info("Invalid userlevel for action")
            return False
            
    @staticmethod
    def isValidFullName(fullName):
        if not isinstance(fullName, str):
            print("Please enter your full name")
            logger.error("Invalid typing on full name")
            return False
            
        if not len(fullName) in range(1..90):
            print("Invalid fullname exceeds 90 character limit")
            logger.info("Invalid fullname exceeds 90 character limit")
            return False
            
        if not ' ' in fullName:
            print("Invalid fullname does not contain a space")
            logger.info("Invalid fullname does not contain a space")
            return False
        
        logging.info("Valid fullname")    
        return True
        
    @staticmethod
    def isValidAddress(address):
        if not isinstance(address, Address):
            print("Please enter your adress")
            logger.error("Invalid typing on adress")
            return False
        
        logging.info("Valid adress")
        return True
            
    @staticmethod
    def isValidStreet(street):
        if not isinstance(street, str):
            print("Please enter your street")
            logger.error("Invalid typing on street")
            return False
            
        if not len(street) in range(1..120):
            print("Invalid street exceeds 90 character limit")
            logger.info("Invalid street exceeds 90 character limit")
            return False
            
        logging.info("Valid street")
        return True
            
    @staticmethod
    def isValidHouseNumber(houseNumber):
        if not isinstance(houseNumber, int):
            print("Please enter your house number")
            logger.error("Invalid typing on houseNumber")
            return False
            
        if houseNumber < 1:
            print("Invalid house number cannot be lower then 1")
            logger.info("Invalid house number cannot be lower then 1")
            return False
        
        logging.info("Valid houseNumber")    
        return True

    @staticmethod
    def isValidZipcode(zipcode):
        zipcodePattern = "[0-9]{4}[A-Z]{2}"
        if not re.match(zipcodePattern, zipcode):
            print("Invalid zipcode, does not match syntax")
            logger.info("Invalid zipcode, does not match syntax")
            return False
        logging.info("Valid zipcode")
        return True

    validCities = ["Bronkhorst", "Sint Anna ter Muiden", "Staverden", "Valkenburg", "Rotterdam", "Sittard", "Middelburg", "Alkmaar", "Delft", "Dordrecht"]
    @staticmethod
    def isValidCity(city):
        if city not in Validators.validCities:
            print("Invalid city, please fill in a valid city)
            logger.info("Invalid city. Does not match with pre defined list")
            return False
        logging.info("Valid city")
        return True

class Client:
    def __init__(self, userLevel, username, password, fullName, address, email, phone):
        self.userLevel = userLevel
        self.username = username
        self.password = password
        self.fullName = fullName
        self.address = address
        self.email = email
        self.phone = phone

class Address:
    def __init__(self, street, houseNumber, zipcode, city):
        self.street = street
        self.houseNumber = houseNumber
        self.zipcode = zipcode
        self.city = city



if __name__ == '__main__':
    isLoggedIn = False

    userlevel = Roles.unauthenticated
    attempts = 0
        
    clients = FileManager.load()
    while not isLoggedIn:
        if attempts >= 3:
            userlevel = Roles.blocked
            print("Blocked out")
            break

        username = input("Fill in username/email: ")
        password = input("Fill in password: ")

        if username == "admin" and password == "geheim":
            print("Succesvol ingelogd")
            userlevel = Roles.superAdministrator
            isLoggedIn = True
            break

        for client in clients:
            if username == client.email and password == client.password:
                print("Succesvol ingelogd")
                userlevel = client.userLevel
                isLoggedIn = True
                break

        if not isLoggedIn:
            print("Verkeerde username en/of wachtwoord")
            attempts = attempts + 1

    while isLoggedIn:
        print("---")
        print("Execute an action. Options: [quit,...]")
        action = input("action: ")
        if action == "quit":
            print("Logged Out.")
            break
        
        print("Action not recognised. Please try again.")



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