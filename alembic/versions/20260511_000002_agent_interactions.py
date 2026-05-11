"""Add agent interactions report table

Revision ID: 20260511_000002
Revises: 20250429_000001
Create Date: 2026-05-11 18:20:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260511_000002"
down_revision = "20250429_000001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_interactions",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_name", sa.String(), nullable=False),
        sa.Column("external_user_id", sa.String(), nullable=True),
        sa.Column("external_username", sa.String(), nullable=True),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("profile_snapshot", sa.JSON(), nullable=True),
        sa.Column("request_text", sa.Text(), nullable=False),
        sa.Column("checks", sa.JSON(), nullable=True),
        sa.Column("verdict", sa.String(), nullable=False),
        sa.Column("trust_score", sa.Float(), nullable=False),
        sa.Column("classification", sa.String(), nullable=False),
        sa.Column("blocked", sa.Boolean(), nullable=True),
        sa.Column("response_text", sa.Text(), nullable=True),
        sa.Column("tool_action", sa.String(), nullable=True),
        sa.Column("tool_details", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_agent_interactions_blocked"), "agent_interactions", ["blocked"], unique=False)
    op.create_index(op.f("ix_agent_interactions_created_at"), "agent_interactions", ["created_at"], unique=False)
    op.create_index(op.f("ix_agent_interactions_external_user_id"), "agent_interactions", ["external_user_id"], unique=False)
    op.create_index(op.f("ix_agent_interactions_external_username"), "agent_interactions", ["external_username"], unique=False)
    op.create_index(op.f("ix_agent_interactions_project_name"), "agent_interactions", ["project_name"], unique=False)
    op.create_index(op.f("ix_agent_interactions_session_id"), "agent_interactions", ["session_id"], unique=False)
    op.create_index(op.f("ix_agent_interactions_verdict"), "agent_interactions", ["verdict"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_agent_interactions_verdict"), table_name="agent_interactions")
    op.drop_index(op.f("ix_agent_interactions_session_id"), table_name="agent_interactions")
    op.drop_index(op.f("ix_agent_interactions_project_name"), table_name="agent_interactions")
    op.drop_index(op.f("ix_agent_interactions_external_username"), table_name="agent_interactions")
    op.drop_index(op.f("ix_agent_interactions_external_user_id"), table_name="agent_interactions")
    op.drop_index(op.f("ix_agent_interactions_created_at"), table_name="agent_interactions")
    op.drop_index(op.f("ix_agent_interactions_blocked"), table_name="agent_interactions")
    op.drop_table("agent_interactions")
