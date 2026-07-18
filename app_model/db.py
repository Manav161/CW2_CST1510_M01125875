import sqlite3
import os

# This points to the database file inside the DATA folder
DB_PATH = os.path.join('DATA', 'project_data.db')

def get_connection():
    #Establishes and returns a connection pipeline to the SQLite database with cross-thread access enabled.
    os.makedirs('DATA', exist_ok=True)
    #Add check_same_thread=False as the second argument here:
    return sqlite3.connect(DB_PATH, check_same_thread=False)