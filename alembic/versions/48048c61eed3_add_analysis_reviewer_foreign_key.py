"""add analysis reviewer foreign key

Revision ID: 48048c61eed3
Revises: 35f759c0c502
Create Date: 2026-08-27 12:27:59.755738

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '48048c61eed3'
down_revision: Union[str, Sequence[str], None] = '35f759c0c502'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add reviewer foreign key."""

    with op.batch_alter_table(
        "analyses",
    ) as batch_op:
        batch_op.create_foreign_key(
            "fk_analyses_reviewed_by_user_id_users",
            "users",
            ["reviewed_by_user_id"],
            ["id"],
        )


def downgrade() -> None:
    """Remove reviewer foreign key."""

    with op.batch_alter_table(
        "analyses",
    ) as batch_op:
        batch_op.drop_constraint(
            "fk_analyses_reviewed_by_user_id_users",
            type_="foreignkey",
        )
