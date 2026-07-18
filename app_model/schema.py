def create_user_table(conn):
    cur = conn.cursor()
    #NOTE:According to indexing id starts from index=0 hence it goes on
    #Defines the table structure for storing user accounts and security fields and for the account lockout policy
    sql = '''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,   
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        dream_car TEXT NOT NULL,
        crush_name TEXT NOT NULL,
        login_attempts INTEGER DEFAULT 0,
        lockout_until TEXT

    );'''
    cur.execute(sql)
    conn.commit()

    