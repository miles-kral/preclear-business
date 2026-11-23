"""catch up missing tables

Revision ID: 7a2c4e9f1b30
Revises: 5c1e9a7d2b40
Create Date: 2026-11-22 12:00:00.000000

Brings the migration history in line with the tables the app actually
uses. evaluation_invitations and password_reset_tokens were created by the
app at startup (create_all) rather than by a migration, so production
already has them; this migration creates them only where they are missing.
It also removes the unused legacy "invitations" table, but only if it is
empty, so no data can be lost.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "7a2c4e9f1b30"
down_revision: Union[str, Sequence[str], None] = "5c1e9a7d2b40"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    tables = _existing_tables()

    if "evaluation_invitations" not in tables:
        op.create_table(
            "evaluation_invitations",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("created_by_user_id", sa.Integer(), nullable=False),
            sa.Column("organization_id", sa.Integer(), nullable=True),
            sa.Column("prospect_name", sa.String(length=180), nullable=False),
            sa.Column("company_name", sa.String(length=180), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("token", sa.String(length=255), nullable=False),
            sa.Column("status", sa.String(length=30), nullable=False),
            sa.Column("access_days", sa.Integer(), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "evaluation_expires_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
            sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_evaluation_invitations_created_by_user_id",
            "evaluation_invitations",
            ["created_by_user_id"],
        )
        op.create_index(
            "ix_evaluation_invitations_email",
            "evaluation_invitations",
            ["email"],
        )
        op.create_index(
            "ix_evaluation_invitations_organization_id",
            "evaluation_invitations",
            ["organization_id"],
        )
        op.create_index(
            "ix_evaluation_invitations_token",
            "evaluation_invitations",
            ["token"],
            unique=True,
        )

    if "password_reset_tokens" not in tables:
        op.create_table(
            "password_reset_tokens",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_password_reset_tokens_token_hash",
            "password_reset_tokens",
            ["token_hash"],
            unique=True,
        )
        op.create_index(
            "ix_password_reset_tokens_user_id",
            "password_reset_tokens",
            ["user_id"],
        )

    # The legacy table was replaced by team_invitations. Remove it only if
    # nothing was ever stored in it.
    if "invitations" in tables:
        count = op.get_bind().execute(
            sa.text("SELECT COUNT(*) FROM invitations")
        ).scalar()

        if count == 0:
            indexes = {
                index["name"]
                for index in sa.inspect(op.get_bind()).get_indexes("invitations")
            }
            if "ix_invitations_organization_id" in indexes:
                op.drop_index(
                    "ix_invitations_organization_id",
                    table_name="invitations",
                )
            op.drop_table("invitations")


def downgrade() -> None:
    # Intentionally does nothing. In production these tables existed
    # before this migration and hold real data (evaluations and password
    # resets), so a downgrade must not remove them.
    pass
