import sqlite3
import bcrypt
import os
import pandas as pd 
import datetime 
import re


#PASSWORD HASHING
BCRYPT_ROUNDS = 12 # work factor hence the computer runs the hashing loop 2^12times
def generate_hash(psw):
    # Salting with a custom work factor loop iteration size
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    byte_psw = psw.encode('utf-8') #bcrypt work with bytes so have to
    hashed = bcrypt.hashpw(byte_psw, salt) # hash the passwrod byter using the salt
    return hashed.decode('utf-8')# retruned as a nrmal string 


def is_valid_hash(psw, stored_hash):
    try:
        # turning both strings into bytes and comparing them to see if they match
        return bcrypt.checkpw(psw.encode('utf-8'), stored_hash.encode('utf-8'))
    except Exception:
        return False #if any error occurs return false instead of crashing 
    


# FLAT-FILE SYSTEM
def register_user_flat_file(name, hash_val):
    os.makedirs('DATA', exist_ok=True)
    with open('DATA/users.txt', 'a') as f:
        f.write(f'{name},{hash_val}\n')

def login_user_flat_file(name, password):
    try:
        with open('DATA/users.txt', 'r') as f:
            for user in f.readlines():
                user_name, user_hash = user.strip().split(',')
                if name == user_name and is_valid_hash(password, user_hash):
                    return True
    except FileNotFoundError:
        return False
    return False



"""
#SQLITE DATABASE CRUD
We use parameterized inputs ('?') to securely update the database without 
risking SQL injection
We use a database cursor to execute direct SQL commands.
"""
def add_user(conn, username, password_hash, dream_car, crush_name):
    try:
        cur = conn.cursor()
        # Changed "password" to "password_hash" in the column definitions below:
        cur.execute(
            "INSERT INTO users (username, password_hash, role, dream_car, crush_name) VALUES (?, ?, ?, ?, ?)",
            (username, password_hash, "User", dream_car, crush_name)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"DATABASE WRITE ERROR: {e}") # This will print the actual error to your terminal if it fails!
        return False
    

def get_user(conn, name):
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username = ?', (name,))
    return cur.fetchone()

#Used for extra safety  
def sanitize_username(username):
    #Strips out dangerous non-alphanumeric characters to prevent SQL Injection inputs.
    if not username:
        return ""
    clean_name = username.strip()#remove extra spaces
    #using re.sub(find and replace tool) to find anything that is NOT a letter or number and deleting it
    clean_name = re.sub(r"[^a-zA-Z0-9]", "", clean_name)
    return clean_name



"""
THe function delete_user, get_all_user, update_user_role are helper functions 
they are used for by the admin who have control over the users 
"""
def delete_user(conn, user_name):
    cur = conn.cursor()
    cur.execute('DELETE FROM users WHERE username = ?', (user_name,))
    conn.commit()

def get_all_users(conn):
    """
    #Fetches registered user accounts to display in the Admin Panel.
    By selecting only 'username' and 'role', we keep the screen clean.
    """
    # Fetch only the columns needed for administrative decisions
    query = "SELECT username, role FROM users"
    return pd.read_sql(query, conn)


def update_user_role(conn, username, new_role):
    #Modifies a user's role designation (e.g., from 'User' to 'Admin').
    cur = conn.cursor()
    
    # Secure parameterized query to update the role column
    query = "UPDATE users SET role = ? WHERE username = ?"
    
    cur.execute(query, (new_role, username))
    conn.commit()



"""
The functions update_lockout, reset_lockot are helper functions
They will be used for the the account lockout policy (Max attempts: 3 tries)
Can be considered a brute force prevention mechansim 

login_attempts (INTEGER, Default: 0) - Tracks consecutive failed attempts.
lockout_until   (TEXT, Default: NULL)   - Stores the ISO timestamp when lock
"""


def update_lockout(conn, username, attempts, lockout_time=None):
    cur = conn.cursor()
    
    # If a lockout timestamp is provided, convert it to an ISO string representation
    # (e.g., '2026-07-17T02:05:00') so SQLite can store it cleanly as text.
    lockout_str = lockout_time.isoformat() if lockout_time else None
    
    # Update both attributes in a single SQL operation
    cur.execute(
        "UPDATE users SET login_attempts = ?, lockout_until = ? WHERE username = ?",
        (attempts, lockout_str, username)
    )
    conn.commit()


def reset_lockout(conn, username):
    cur = conn.cursor()
    
    # Reset attempts to 0 and clear the lockout time to NULL so as next session donot get mixed up
    cur.execute(
        "UPDATE users SET login_attempts = 0, lockout_until = NULL WHERE username = ?",
        (username,)
    )
    conn.commit()