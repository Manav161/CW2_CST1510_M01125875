import bcrypt
# Define the secret password 
password = "Ben10###".encode('utf-8')

# Generate a random salt with a cost factor of 12, then hash the password
hashed_password = bcrypt.hashpw(password, bcrypt.gensalt(12))
#the result printed is used to hard code the admin credentials 
print(hashed_password)