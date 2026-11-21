"""add analysis type, target and details

Revision ID: 5c1e9a7d2b40
Revises: 48048c61eed3
Create Date: 2026-11-21 12:00:00.000000

Lets the analyses table hold email, link and QR results alongside file
results. Existing rows become analysis_type "file".
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "5c1e9a7d2b40"
down_revision: Union[str, Sequence[str], None] = "48048c61eed3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add analysis_type, target and details_json to analyses."""

    with op.batch_alter_table(
        "analyses",
    ) as batch_op:
        batch_op.add_column(
            sa.Column(
                "analysis_type",
                sa.String(length=20),
                server_default="file",
                nullable=False,
            )
        )

        batch_op.add_column(
            sa.Column(
                "target",
                sa.Text(),
                nullable=True,
            )
        )

        batch_op.add_column(
            sa.Column(
                "details_json",
                sa.Text(),
                nullable=True,
            )
        )

        batch_op.create_index(
            "ix_analyses_analysis_type",
            ["analysis_type"],
        )


def downgrade() -> None:
    """Remove analysis_type, target and details_json."""

    with op.batch_alter_table(
        "analyses",
    ) as batch_op:
        batch_op.drop_index(
            "ix_analyses_analysis_type",
        )

        batch_op.drop_column("details_json")
        batch_op.drop_column("target")
        batch_op.drop_column("analysis_type")
