import logging, re, operator, json

logging.basicConfig(filename='log.log', level=logging.DEBUG, format='%(levelname)s: %(asctime)s %(message)s')

print("\t*****************************************")
print("\t***  Welcome in the software quality  ***")
print("\t*****************************************")


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
        allowed_chars = lower + upper + digits + chars

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

    createable_roles = [systemAdministrator, advisor]

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
        allowed_chars = lower + upper + digits + chars

        containregexpattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[~!@#$%^&*_\-+=`|\\(){}[\]:;'<>,.?/])"

        if len(password) not in range(8, 31):
            print("Invalid because password not between 8 and 30 characters")
            logging.info("Invalid because password not between 8 and 30 characters")
            return False

        for char in password:
            if char not in allowed_chars:
                print("Invalid because password contains invalid character")
                logging.info("Invalid because password contains invalid character")
                return False

        if not re.match(containregexpattern, password):
            print("Invalid because password does not contain 1 uppercase, 1 lowercase, 1 digit or 1 special character")
            logging.info("Invalid because password does not contain 1 uppercase, 1 lowercase, 1 digit or 1 special character")
            return False
        logging.info("Valid password")
        return True

    @staticmethod
    def isValidUsername(username):
        value = username.lower()

        lower = "abcdefghijklmnopqrstuvwxyz"
        digits = "0123456789"
        chars = "_-'."
        allowed_chars = lower + digits + chars

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
        if not houseNumber.isnumeric():
            print("Please enter your house number")
            logging.error("Invalid typing on houseNumber")
            return False

        if int(houseNumber) < 1:
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

    validCities = ["Bronkhorst", "Sint Anna ter Muiden", "Staverden", "Valkenburg", "Rotterdam", "Sittard",
                   "Middelburg", "Alkmaar", "Delft", "Dordrecht"]

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


superAdmin = Client(
    Roles.superAdministrator,
    "admin",
    "admin",
    "admin admin",
    Address(
        "Admin",
        1,
        "0000AD",
        "Rotterdam"
    ),
    "admin@admin.admin",
    "+31-6-0000-0000"
)


def create_client(userLevel):
    if userLevel not in Roles.createable_roles:
        print("You do not have permission to execute this action. For suspicious behaviour you have been blocked. Please contact the administrator.")
        logging.warning(currentClient.username + " has been blocked for suspicious behaviour.")
        currentClient.userLevel = Roles.blocked
        FileManager.save(clients)
        return False

    attempts = 0
    username = input("Username:")
    while not Validators.isValidUsername(username):
        if attempts > 3:
            return False
        attempts = attempts + 1
        username = input("Username:")

    attempts = 0
    password = input("Password:")
    while not Validators.isValidPassword(password):
        if attempts > 3:
            return False
        attempts = attempts + 1
        password = input("Password:")

    attempts = 0
    fullName = input("Full Name:")
    while not Validators.isValidFullName(fullName):
        if attempts > 3:
            return False
        attempts = attempts + 1
        fullName = input("Full Name:")

    attempts = 0
    email = input("Email:")
    while not Validators.isValidEmail(email):
        if attempts > 3:
            return False
        attempts = attempts + 1
        email = input("Email:")

    attempts = 0
    phone = input("Phone:")
    while not Validators.isValidPhone(phone):
        if attempts > 3:
            return False
        attempts = attempts + 1
        phone = input("Phone:")

    attempts = 0
    street = input("Street:")
    while not Validators.isValidStreet(street):
        if attempts > 3:
            return False
        attempts = attempts + 1
        street = input("Street:")

    attempts = 0
    houseNumber = input("House Number:")
    while not Validators.isValidHouseNumber(houseNumber):
        if attempts > 3:
            return False
        attempts = attempts + 1
        houseNumber = input("House Number:")
    houseNumber = int(houseNumber)

    attempts = 0
    zipCode = input("Zip Code:")
    while not Validators.isValidZipcode(zipCode):
        if attempts > 3:
            return False
        attempts = attempts + 1
        zipCode = input("Zip Code:")

    print("Please select a city from this list (CASE SENSITIVE): ", Validators.validCities)
    city = input("City:")
    if not Validators.isValidCity(city):
        # Immediately cancels creation of a client if the city is incorrect.
        # This is because we see the city as system-generated input. 
        return False

    clients.append(
        Client(
            userLevel,
            username,
            password,
            fullName,
            Address(
                street,
                houseNumber,
                zipCode,
                city
            ),
            email,
            phone
        )
    )
    FileManager.save(clients)

    return True


clients = []
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
            logging.warning("Too many failed login attempts")
            break

        username = input("Fill in username/email: ")
        password = input("Fill in password: ")

        if username == superAdmin.username and password == superAdmin.password:
            print("Logged in successfull")
            logging.info("Logged as super administrator")
            userlevel = Roles.superAdministrator
            currentClient = superAdmin
            isLoggedIn = True
            break

        for client in clients:
            if username == client.email and password == client.password:
                if Roles.allow_login(client):
                    print("Logged in successfull")
                    userlevel = client.userLevel
                    currentClient = client
                    isLoggedIn = True
                    break
                else:
                    print("You are unauthorized to log in. Please contact a system administrator if you think this is an error.")
                    logging.warning("Unauthorized user '" + username + "' attempted to log in.")
                    break

        if not isLoggedIn:
            print("Wrong username and/or password")
            attempts += 1

    afterLoginAttemps = 0

    while isLoggedIn:
        if afterLoginAttemps >= 3:
            print("You did too many attempts on actions where you do not have permission for. You are now blocked. Please contact the administrator")
            logging.warning(currentClient.username + " has been blocked for attempting to reach actions without permission.")
            currentClient.userLevel = Roles.blocked
            FileManager.save(clients)
            break

        if not Roles.allow_login(currentClient):
            print("This account has been deauthorized. Please contact a system administrator if you think this is an error.")
            logging.warning("Unauthorized user '" + username + "' attempted to log in.")
            break

        print("---")
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
                afterLoginAttemps += 1
                print("You do not have permission to execute this action")
                logging.info(currentClient.username + " does not have permission to create advisor. attempt: " + str(afterLoginAttemps))
                continue

            if create_client(Roles.advisor):
                print("Advisor created!")
            else:
                afterLoginAttemps += 1
            continue

        if action == "create_system_admin":
            if not Roles.allow_creating_system_admin(currentClient):
                afterLoginAttemps += 1
                print("You do not have permission to execute this action")
                logging.info(currentClient.username + " does not have permission to create system admin. attempt: " + str(afterLoginAttemps))
                continue

            if create_client(Roles.systemAdministrator):
                print("Advisor created!")
            else:
                afterLoginAttemps += 1
            continue

        if action == "read_log":
            if not Roles.allow_reading_log(currentClient):
                afterLoginAttemps += 1
                print("You do not have permission to execute this action")
                logging.info(currentClient.username + " does not have permission to see log. attempt: " + str(afterLoginAttemps))
                continue

            file = open("log.log", "r")
            print(file.read())
            file.close()
            continue

        print("Action not recognised. Please try again.")
