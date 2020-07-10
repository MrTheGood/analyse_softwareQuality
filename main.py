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
                client["full_name"], 
                Address(
                    address["street"],
                    address["houseNumber"],
                    address["zip"],
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


class Client:
    def __init__(self, userLevel, username, password, full_name, address, email, phone):
        self.userLevel = userLevel
        self.username = username
        self.password = password
        self.full_name = full_name
        self.address = address
        self.email = email
        self.phone = phone

    mailpattern = "[a-zA-Z0-9\\+\\.\\_\\%\\-\\+]{1,256}\\@[a-zA-Z0-9][a-zA-Z0-9\\-]{0,64}(\\.[a-zA-Z0-9][a-zA-Z0-9\\-]{0,25})+"
    phonepattern = "\+31-6-[0-9]{4}-[0-9]{4}"

    email = property(operator.attrgetter('_email'))
    phone = property(operator.attrgetter('_phone'))
    
    username = property(operator.attrgetter('_username'))
    password = property(operator.attrgetter('_password'))


    @email.setter
    def email(self, d):
        if not re.match(self.mailpattern, d):
            print("mailadres not valid!")

    @phone.setter
    def phone(self, d):
        if not re.match(self.phonepattern, d):
            print("phone number invalid!")

    @password.setter
    def password(self, value):
        lower = "abcdefghijklmnopqrstuvwxyz"
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        chars = "~!@#$%^&*_-+=`|\\(){}[]:;'<>,.?/"
        allowed_chars = lower+upper+digits+chars

        containregexpattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]$"

        if len(value) not in range(8, 31):
            return False

        if not re.match(containregexpattern, value):
            return False

        for char in value:
            if char not in allowed_chars:
                return False
        return True

    @username.setter
    def username(self, value):
        value = value.lower()

        lower = "abcdefghijklmnopqrstuvwxyz"
        digits = "0123456789"
        chars = "_-'."
        allowed_chars = lower+digits+chars

        if len(value) not in range(5, 21):
            return False

        if not value[0].isalpha():
            return False

        for char in value:
            if char not in allowed_chars:
                return False
        return True



class Address:
    def __init__(self, street, houseNumber, zipcode, city):
        self.street = street
        self.houseNumber = houseNumber
        self.zipcode = zipcode
        self.city = city
    
    city_whitelist = ["Bronkhorst", "Sint Anna ter Muiden", "Staverden", "Valkenburg", "Rotterdam", "Sittard", "Middelburg", "Alkmaar", "Delft", "Dordrecht"]
    zipcodepattern = "[0-9]{4}[a-zA-Z]{2}"

    zipcode = property(operator.attrgetter('_zipcode'))
    city = property(operator.attrgetter('_city'))

    @zipcode.setter
    def zipcode(self, d):
        if not re.match(self.zipcodepattern, d):
            raise ValueError('Zipcode Invalid')

    @city.setter
    def city(self, d):
        if not d in self.city_whitelist:
            raise ValueError('City Invalid')
            





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

        username = input("Fill in username: ")
        password = input("Fill in password: ")

        if username == "admin" and password == "geheim":
            print("Succesvol ingelogd")
            userlevel = Roles.superAdministrator
            isLoggedIn = True
        else:
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




# all these validations: 
# Client should have the following data:
# - Full Name
# - Addres 
#   - Street + House Number
#   - Zip Code (DDDDXX)
#   - City (should match a city in a list of 10 city names)
# - Email Adress
# - Mobile Phone (+31-6-DDDD-DDDD)




# password:
# length: 8..30
# abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789 ~!@#$%^&*_-+=`|\(){}[]:;'<>,.?/






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