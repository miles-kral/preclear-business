import sqlite3

from app.config import DATABASE_PATH


columns = {
    "subscription_cancel_at_period_end": (
        "BOOLEAN NOT NULL DEFAULT 0"
    ),
    "subscription_current_period_end": (
        "DATETIME"
    ),
}


connection = sqlite3.connect(
    DATABASE_PATH
)

try:
    existing_columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(organizations)"
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
            ALTER TABLE organizations
            ADD COLUMN {column_name} {column_type}
            """
        )

        print(
            f"{column_name}: added"
        )

    connection.commit()

finally:
    connection.close()