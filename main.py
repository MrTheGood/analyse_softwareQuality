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
        chars = r"~!@\"#$%^&*_-+=`|\(){}[]:;'<>,.?/"
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
    blocked = 4

    @staticmethod
    def allow_login(client):
        return client.userLevel in [Roles.superAdministrator, Roles.systemAdministrator, Roles.advisor]

    @staticmethod
    def allow_creating_advisor(client):
        return client.userLevel in [Roles.systemAdministrator]

    @staticmethod
    def allow_creating_system_admin(client):
        return client.userLevel in [Roles.superAdministrator]

    @staticmethod
    def allow_reading_log(client):
        return client.userLevel in [Roles.superAdministrator, Roles.systemAdministrator]


class Validators:
    @staticmethod
    def isValidEmail(email):
        mailpattern = r"[a-zA-Z0-9\+\.\_\%\-\+]{1,256}\@[a-zA-Z0-9][a-zA-Z0-9\-]{0,64}(\.[a-zA-Z0-9][a-zA-Z0-9\-]{0,25})+"
        if re.match(mailpattern, email):
            logging.info("Valid email")
            return True
        else: 
            print("Invalid email, does not match syntax")
            logging.info("Invalid email, does not match syntax")
            return False

    @staticmethod
    def isValidPhone(phone):
        phonepattern = r"\+31-6-[0-9]{4}-[0-9]{4}"
        if re.match(phonepattern, phone):
            logging.info("Valid phone number")
            return True
        else: 
            print("Invalid phone number, does not match syntax")
            logging.info("Invalid phone number, does not match syntax")
            return False

    @staticmethod
    def isValidPassword(password):
        lower = "abcdefghijklmnopqrstuvwxyz"
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        chars = r"~!@#$%^&*_-+=`|\(){}[]:;'<>,.?/"
        allowed_chars = lower+upper+digits+chars

        containregexpattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]$"

        if len(password) not in range(8, 31):
            print("Invalid because password not between 8 and 30 characters")
            logging.info("Invalid because password not between 8 and 30 characters")
            return False

        if not re.match(containregexpattern, password):
            print("Invalid because password does not contain 1 uppercase, 1 lowercase, 1 digit or 1 special character")
            logging.info("Invalid because password does not contain 1 uppercase, 1 lowercase, 1 digit or 1 special character")
            return False

        for char in password:
            if char not in allowed_chars:
                print("Invalid because password contains invalid character")
                logging.info("Invalid because password contains invalid character")
                return False
        logging.info("Valid password")
        return True


    @staticmethod
    def isValidUsername(username):
        value = username.lower()

        lower = "abcdefghijklmnopqrstuvwxyz"
        digits = "0123456789"
        chars = "_-'."
        allowed_chars = lower+digits+chars

        if len(value) not in range(5, 21):
            print("Invalid because username not between 5 and 20 characters")
            logging.info("Invalid because username not between 5 and 20 characters")
            return False

        if not value[0].isalpha():
            print("Invalid because username does not start with a letter")
            logging.info("Invalid because username does not start with a letter")
            return False

        for char in value:
            if char not in allowed_chars:
                print("Invalid because username contains invalid character")
                logging.info("Invalid because username contains invalid character")
                return False
        logging.info("Valid username")
        return True
        
    @staticmethod
    def isValidClientUserLevel(userLevel):
        if userLevel in [Roles.systemAdministrator, Roles.advisor]:
            logging.info("Valid userlevel")
            return True
        else:
            print("Invalid userlevel for action")
            logging.info("Invalid userlevel for action")
            return False
            
    @staticmethod
    def isValidFullName(fullName):
        if not isinstance(fullName, str):
            print("Please enter your full name")
            logging.error("Invalid typing on full name")
            return False
            
        if not len(fullName) in range(1, 90):
            print("Invalid fullname exceeds 90 character limit")
            logging.info("Invalid fullname exceeds 90 character limit")
            return False
            
        if not ' ' in fullName:
            print("Invalid fullname does not contain a space")
            logging.info("Invalid fullname does not contain a space")
            return False
        
        logging.info("Valid fullname")    
        return True
        
    @staticmethod
    def isValidAddress(address):
        if not isinstance(address, Address):
            print("Please enter your adress")
            logging.error("Invalid typing on adress")
            return False
        
        logging.info("Valid adress")
        return True
            
    @staticmethod
    def isValidStreet(street):
        if not isinstance(street, str):
            print("Please enter your street")
            logging.error("Invalid typing on street")
            return False
            
        if not len(street) in range(1, 120):
            print("Invalid street exceeds 90 character limit")
            logging.info("Invalid street exceeds 90 character limit")
            return False
            
        logging.info("Valid street")
        return True
            
    @staticmethod
    def isValidHouseNumber(houseNumber):
        if not isinstance(houseNumber, int):
            print("Please enter your house number")
            logging.error("Invalid typing on houseNumber")
            return False
            
        if houseNumber < 1:
            print("Invalid house number cannot be lower then 1")
            logging.info("Invalid house number cannot be lower then 1")
            return False
        
        logging.info("Valid houseNumber")    
        return True

    @staticmethod
    def isValidZipcode(zipcode):
        zipcodePattern = "[0-9]{4}[A-Z]{2}"
        if not re.match(zipcodePattern, zipcode):
            print("Invalid zipcode, does not match syntax")
            logging.info("Invalid zipcode, does not match syntax")
            return False
        logging.info("Valid zipcode")
        return True

    validCities = ["Bronkhorst", "Sint Anna ter Muiden", "Staverden", "Valkenburg", "Rotterdam", "Sittard", "Middelburg", "Alkmaar", "Delft", "Dordrecht"]
    @staticmethod
    def isValidCity(city):
        if city not in Validators.validCities:
            print("Invalid city, please fill in a valid city")
            logging.info("Invalid city. Does not match with pre defined list")
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
    currentClient = None
    attempts = 0
        
    clients = FileManager.load()
    while not isLoggedIn:
        if attempts >= 3:
            userlevel = Roles.blocked
            print("Too many failed login attempts")
            logging.warn("Too many failed login attempts")
            break

        username = input("Fill in username/email: ")
        password = input("Fill in password: ")

        if username == "admin" and password == "geheim":
            print("Logged in successfull")
            logging.info("Logged as super administrator")
            userlevel = Roles.superAdministrator
            isLoggedIn = True
            break

        for client in clients:
            if username == client.email and password == client.password :
                if Roles.allow_login(client):
                    print("Logged in successfull")
                    userlevel = client.userLevel
                    currentClient = client
                    isLoggedIn = True
                    break
                else: 
                    print("You are unauthorized to log in. Please contact a system administrator if you think this is an error.")
                    logging.warn("Unauthorized user '" + username + "' attempted to log in.")
                    break

        if not isLoggedIn:
            print("Wrong username and/or password")
            attempts = attempts + 1


    while isLoggedIn:
        print("---")
        print(",...]")
        availableOptions = "Execute an action. Options: [quit"

        if Roles.allow_creating_advisor(currentClient):
            availableOptions = availableOptions + ", create_advisor"

        if Roles.allow_creating_system_admin(currentClient):
            availableOptions = availableOptions + ", create_system_admin"

        if Roles.allow_reading_log(currentClient):
            availableOptions = availableOptions + ", read_log"

        availableOptions = availableOptions + "]"
        print(availableOptions)
            
        action = input("action: ")
        if action == "quit":
            print("Logged Out.")
            break

        if action == "create_advisor":
            if not Roles.allow_creating_advisor(currentClient):
                #todo: do
                continue
            # todo: do
            continue

        if action == "create_system_admin":
            if not Roles.allow_creating_system_admin(currentClient):
                #todo: do
                continue
            # todo: do
            continue

        if action == "read_log":
            if not Roles.allow_reading_log(currentClient):
                #todo: do
                continue
            # todo: do
            continue
        
        print("Action not recognised. Please try again.")

# TODO: C4 Invalid inputs are properly handled.
# ▪ In case of invalid input by user, the system must take appropriate action. For example, it might only display a 
# proper message to the user, or might ban the user for extra attempts, depends on the number of invalid inputs for a specific field.

# TODO: C5 Suspicious activities are logged.
# ▪ In case of suspicious activities or realizing an attack; for example, a user is attacking the system by trying many 
# passwords (brute force), or an open session is used by a stranger and entering suspicious characters in irrelevant 
# fields of data (e.g. entering ‘/’ in user name multiple times); then the system need to take proper action, and log 
# the activity in a file. This file must be available only to Super Administrator or System Administrator in menu options.