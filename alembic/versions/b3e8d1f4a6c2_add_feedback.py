"""add feedback

Revision ID: b3e8d1f4a6c2
Revises: 9d4f6b2a8c51
Create Date: 2026-11-27 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "b3e8d1f4a6c2"
down_revision: Union[str, Sequence[str], None] = "9d4f6b2a8c51"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Created only if missing, so a database that already has the table
    # (for example from a test run) can still be upgraded.
    if "feedback" in sa.inspect(op.get_bind()).get_table_names():
        return

    op.create_table(
        "feedback",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("category", sa.String(length=20), nullable=False),
        sa.Column("rating", sa.Integer(), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("page", sa.String(length=300), nullable=True),
        sa.Column("browser", sa.String(length=300), nullable=True),
        sa.Column("may_contact", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_feedback_organization_id", "feedback", ["organization_id"])
    op.create_index("ix_feedback_status", "feedback", ["status"])
    op.create_index("ix_feedback_created_at", "feedback", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_feedback_created_at", table_name="feedback")
    op.drop_index("ix_feedback_status", table_name="feedback")
    op.drop_index("ix_feedback_organization_id", table_name="feedback")
    op.drop_table("feedback")
