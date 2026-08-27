import sqlite3

from app.config import DATABASE_PATH


columns = {
    "virustotal_found": "BOOLEAN",
    "virustotal_malicious": "INTEGER",
    "virustotal_suspicious": "INTEGER",
    "virustotal_undetected": "INTEGER",
    "virustotal_harmless": "INTEGER",
    "virustotal_error": "VARCHAR(80)",
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

    for column_name, column_type in columns.items():

        if column_name in existing_columns:
            print(
                f"{column_name}: already exists"
            )
            continue

        connection.execute(
            f"""
            ALTER TABLE analyses
            ADD COLUMN {column_name} {column_type}
            """
        )

        print(
            f"{column_name}: added"
        )

    connection.commit()

finally:
    connection.close()