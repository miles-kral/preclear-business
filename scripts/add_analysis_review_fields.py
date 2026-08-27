import sqlite3

from app.config import DATABASE_PATH


columns = {
    "review_status": (
        "ALTER TABLE analyses "
        "ADD COLUMN review_status "
        "VARCHAR(30) NOT NULL DEFAULT 'open'"
    ),
    "reviewed_at": (
        "ALTER TABLE analyses "
        "ADD COLUMN reviewed_at DATETIME"
    ),
    "reviewed_by_user_id": (
        "ALTER TABLE analyses "
        "ADD COLUMN reviewed_by_user_id INTEGER"
    ),
    "resolution_note": (
        "ALTER TABLE analyses "
        "ADD COLUMN resolution_note TEXT"
    ),
}


connection = sqlite3.connect(
    DATABASE_PATH
)

try:
    existing_columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(analyses)"
        ).fetchall()
    }

    for column_name, sql in columns.items():

        if column_name in existing_columns:
            print(
                f"Already exists: {column_name}"
            )
            continue

        connection.execute(sql)

        print(
            f"Added: {column_name}"
        )

    connection.commit()

    final_columns = [
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(analyses)"
        ).fetchall()
    ]

    print("\nAnalysis columns:")

    for column_name in final_columns:
        print(
            f"  {column_name}"
        )

finally:
    connection.close()