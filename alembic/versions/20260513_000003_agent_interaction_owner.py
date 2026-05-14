"""Add CIVS owner to agent interaction reports

Revision ID: 20260513_000003
Revises: 20260511_000002
Create Date: 2026-05-13 14:10:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260513_000003"
down_revision = "20260511_000002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_interactions", sa.Column("civs_user_id", sa.String(), nullable=True))
    op.create_index(
        op.f("ix_agent_interactions_civs_user_id"),
        "agent_interactions",
        ["civs_user_id"],
        unique=False,
    )
    op.create_foreign_key(
        "fk_agent_interactions_civs_user_id_users",
        "agent_interactions",
        "users",
        ["civs_user_id"],
        ["id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_agent_interactions_civs_user_id_users",
        "agent_interactions",
        type_="foreignkey",
    )
    op.drop_index(op.f("ix_agent_interactions_civs_user_id"), table_name="agent_interactions")
    op.drop_column("agent_interactions", "civs_user_id")
