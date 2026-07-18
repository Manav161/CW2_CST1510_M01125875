import pandas as pd
# import sqlite3

def migrate_cyber_incidents(conn):
    #Reads the cyber_incidents.csv file from the DATA folder  and saves it inside the SQLite database as a table.
    try:
        # 1. Read the raw data file using pandas
        df = pd.read_csv('DATA/cyber_incidents.csv')
        
        # 2. Save it into our database table named 'cyber_incidents'
        # if_exists='replace' means if the table is already there, overwrite it cleanly
        df.to_sql('cyber_incidents', conn, if_exists='replace', index=False)
        return True
    except Exception as e:#handles error but englobes all error that it check against 
        print(f"Error moving cyber incidents data: {e}")
        return False


def get_all_cyber_incidents(conn):
    #Queries the database table and returns the data 
    #as a clean table format (DataFrame) for Streamlit to show.
    query = "SELECT * FROM cyber_incidents"
    df = pd.read_sql(query, conn)
 
    # Convert the timestamp column to datetime
    # Format it to keep only Hours:Minutes:Seconds
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp']).dt.strftime('%H:%M:%S')
        
    return df