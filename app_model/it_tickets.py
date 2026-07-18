import pandas as pd
import sqlite3

def migrate_it_tickets(conn):
    #Reads the it_tickets.csv file from the DATA folder 
    #and saves it inside the SQLite database as a table.
    try:
        # 1. Read the raw data file using pandas
        df = pd.read_csv('DATA/it_tickets.csv')
        
        # 2. Save it in db table named 'it_tickets'
        df.to_sql('it_tickets', conn, if_exists='replace', index=False)
        return True
    except Exception as e:#handles error but englobes all error that it check against 
        print(f"Error moving IT tickets data: {e}")
        return False

def get_all_it_tickets(conn):
    #Queries the database table and returns the data 
    #as a clean table format (DataFrame) for Streamlit to show.
    query = "SELECT * FROM it_tickets"
    return pd.read_sql(query, conn)