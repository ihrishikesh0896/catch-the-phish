import sqlite3

def init_db():
    conn = sqlite3.connect('phish_tank.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_url TEXT NOT NULL,
    domain TEXT NOT NULL,
    ip_address TEXT,
    hosting_provider TEXT,
    score INTEGER NOT NULL,
    status TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);
    ''')
    conn.commit()
    conn.close()

# Call this function when the app starts to ensure the table exists
# init_db()
