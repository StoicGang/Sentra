
import sqlite3
conn = sqlite3.connect('data/vault.db')
conn.row_factory = sqlite3.Row
rows = conn.execute(\"SELECT id, title, tags FROM entries WHERE is_deleted = 0\").fetchall()
for r in rows:
    print(dict(r))
conn.close()
