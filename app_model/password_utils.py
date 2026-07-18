import secrets# allows access to a pre made list of characters  
import string # used to generate random num for passwords
import re       # Needed for regular expressions to check password requirements

def generate_secure_password(length=12):
    """Generates a cryptographically strong random password satisfying all complexity requirements
       Combine lowercase letters, uppercase letters, numbers, and symbols into one character pool"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+"

    #Loop Runs until all the requirement have been met
    while True:
        # create a passwrd of length 12 from the random combination of the character from the pool created above
        password = ''.join(secrets.choice(alphabet) for _ in range(length))  
        #check if it matches all these criteria also:
        if (any(c.islower() for c in password) #has atleast one lowercase letter
                and any(c.isupper() for c in password) # has at least one uppercase letter 
                and any(c.isdigit() for c in password)# has at least one number
                and any(c in "!@#$%^&*()_+" for c in password)):#has at least one special character 
            return password
        


def is_strong_password(password):
    if not password or len(password.strip()) == 0:
        return False, ["Password cannot be left blank."]
    #an empty list gets created to track the requirement still missing
    missing = []
    #re.search can be as if this does scanning 
    #so this checks if all requirements for what a secured password is needed is met 
    #missing.append will update the list if requirments are missing 
    if len(password) < 8: missing.append("At least 8 characters long")
    if not re.search(r"[A-Z]", password): missing.append("At least 1 uppercase letter (A-Z)")
    if not re.search(r"[a-z]", password): missing.append("At least 1 lowercase letter (a-z)")
    if not re.search(r"[0-9]", password): missing.append("At least 1 numeric digit (0-9)")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_+\-\[\]\/\\]", password):
        missing.append("At least 1 special symbol (@, #, $, etc.)")
    #if the missing list is empty that means the password met all the criteria hence good to go through
    return len(missing) == 0, missing


