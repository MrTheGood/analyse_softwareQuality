print("\t**********************************************")
print("\t***  Greeter - Hello old and new friends!  ***")
print("\t**********************************************")

notLoggedIn = True

while notLoggedIn:
    if tries == 3:
        print("Blocked out")

    username = input("Fill in username: ")
    password = input("Fill in password: ")

    tries = 0

    if username == "admin" and password == "geheim":
        print("Succesvol ingelogd")
        notLoggedIn = False
    else:
        tries + 1










# password:
# length: 8..30
# abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789 ~!@#$%^&*_-+=`|\(){}[]:;'<>,.?/.




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