import sqlite3

from app.config import DATABASE_PATH


connection = sqlite3.connect(
    DATABASE_PATH
)

try:
    existing_columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(team_invitations)"
        ).fetchall()
    }

    if "delivery_status" not in existing_columns:
        connection.execute(
            """
            ALTER TABLE team_invitations
            ADD COLUMN delivery_status
            VARCHAR(30) NOT NULL DEFAULT 'pending'
            """
        )

    if "last_delivery_error" not in existing_columns:
        connection.execute(
            """
            ALTER TABLE team_invitations
            ADD COLUMN last_delivery_error TEXT
            """
        )

    connection.commit()

    print(
        [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(team_invitations)"
            ).fetchall()
        ]
    )

finally:
    connection.close()