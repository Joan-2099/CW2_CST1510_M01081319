import sqlite3

conn = sqlite3.connect("my_database.db")
cursor = conn.cursor()
cursor.execute("SOME SQL HERE")
conn.commit()
conn.close()
