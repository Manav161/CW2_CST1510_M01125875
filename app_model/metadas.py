import pandas as pd

def migrate_metadata(conn):
   # Reads the datasets_metadata.csv file from the DATA folder 
   #and saves it inside the SQLite database as a table.
    try:
        #Read the raw data file using pandas
        df = pd.read_csv('DATA/datasets_metadata.csv')
        
        #Save it into db table named 'metadata'
        df.to_sql('metadata', conn, if_exists='replace', index=False)
        return True
    except Exception as e:#handles error but englobes all error that it check against 
        print(f"Error moving metadata data: {e}")
        return False

def get_all_metadata(conn):
    #Queries the database table and returns the data 
    #as a clean table format (DataFrame) for Streamlit to show.
    query = "SELECT * FROM metadata"
    return pd.read_sql(query, conn)