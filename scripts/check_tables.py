import sqlite3

from app.config import DATABASE_PATH


connection = sqlite3.connect(
    DATABASE_PATH
)

try:
    tables = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        ORDER BY name
        """
    ).fetchall()

    print("Database tables:")

    for table in tables:
        print(
            f"  {table[0]}"
        )

finally:
    connection.close()