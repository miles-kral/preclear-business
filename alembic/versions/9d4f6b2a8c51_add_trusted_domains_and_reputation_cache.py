"""add trusted domains and reputation cache

Revision ID: 9d4f6b2a8c51
Revises: 7a2c4e9f1b30
Create Date: 2026-11-22 12:30:00.000000

The app also creates missing tables at startup (create_all in main.py), so
if the server ran with the new code before this migration, these tables
may already exist. Each table and index is created only if it's missing.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "9d4f6b2a8c51"
down_revision: Union[str, Sequence[str], None] = "7a2c4e9f1b30"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _existing_indexes(table: str) -> set[str]:
    return {
        index["name"]
        for index in sa.inspect(op.get_bind()).get_indexes(table)
    }


def upgrade() -> None:
    tables = _existing_tables()

    if "trusted_domains" not in tables:
        op.create_table(
            "trusted_domains",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("organization_id", sa.Integer(), nullable=False),
            sa.Column("domain", sa.String(length=253), nullable=False),
            sa.Column("label", sa.String(length=120), nullable=False),
            sa.Column("kind", sa.String(length=20), nullable=False),
            sa.Column("created_by_user_id", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
            sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "organization_id",
                "domain",
                name="uq_trusted_domains_organization_domain",
            ),
        )

    if "ix_trusted_domains_organization_id" not in _existing_indexes(
        "trusted_domains"
    ):
        op.create_index(
            "ix_trusted_domains_organization_id",
            "trusted_domains",
            ["organization_id"],
        )

    if "reputation_cache" not in tables:
        op.create_table(
            "reputation_cache",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("kind", sa.String(length=10), nullable=False),
            sa.Column("lookup_key", sa.String(length=253), nullable=False),
            sa.Column("result_json", sa.Text(), nullable=False),
            sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "kind",
                "lookup_key",
                name="uq_reputation_cache_kind_key",
            ),
        )

    if "ix_reputation_cache_fetched_at" not in _existing_indexes(
        "reputation_cache"
    ):
        op.create_index(
            "ix_reputation_cache_fetched_at",
            "reputation_cache",
            ["fetched_at"],
        )


def downgrade() -> None:
    op.drop_index(
        "ix_reputation_cache_fetched_at",
        table_name="reputation_cache",
    )
    op.drop_table("reputation_cache")

    op.drop_index(
        "ix_trusted_domains_organization_id",
        table_name="trusted_domains",
    )
    op.drop_table("trusted_domains")