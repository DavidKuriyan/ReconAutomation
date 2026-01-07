import sqlite3

def init_db():
    try:
        conn = sqlite3.connect('aether.db')
        cursor = conn.cursor()
        
        with open('schema.sql', 'r') as f:
            schema = f.read()
            
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.executescript(schema)
        conn.commit()
        print("Database (SQLite) initialized successfully with V3 OSINT Schema (WAL Mode Enabled).")
        
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error initializing DB: {e}")

if __name__ == "__main__":
    init_db()
