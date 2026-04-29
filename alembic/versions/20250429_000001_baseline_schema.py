"""Baseline schema

Revision ID: 20250429_000001
Revises:
Create Date: 2026-04-29 17:10:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20250429_000001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "certificates",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("key_type", sa.String(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("cert_metadata", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "security_events",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("context_id", sa.String(), nullable=True),
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_security_events_context_id"), "security_events", ["context_id"], unique=False)
    op.create_index(op.f("ix_security_events_created_at"), "security_events", ["created_at"], unique=False)
    op.create_index(op.f("ix_security_events_event_type"), "security_events", ["event_type"], unique=False)
    op.create_index(op.f("ix_security_events_user_id"), "security_events", ["user_id"], unique=False)

    op.create_table(
        "users",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("is_admin", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.create_index(op.f("ix_users_username"), "users", ["username"], unique=True)

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("resource_type", sa.String(), nullable=False),
        sa.Column("resource_id", sa.String(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("user_agent", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_audit_logs_action"), "audit_logs", ["action"], unique=False)
    op.create_index(op.f("ix_audit_logs_created_at"), "audit_logs", ["created_at"], unique=False)
    op.create_index(op.f("ix_audit_logs_resource_id"), "audit_logs", ["resource_id"], unique=False)
    op.create_index(op.f("ix_audit_logs_user_id"), "audit_logs", ["user_id"], unique=False)

    op.create_table(
        "data_sources",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("source_type", sa.String(), nullable=False),
        sa.Column("config", sa.JSON(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_data_sources_user_id"), "data_sources", ["user_id"], unique=False)

    op.create_table(
        "context_records",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("parent_context_id", sa.String(), nullable=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(), nullable=False),
        sa.Column("previous_hash", sa.String(), nullable=True),
        sa.Column("context_metadata", sa.JSON(), nullable=True),
        sa.Column("context_type", sa.String(), nullable=True),
        sa.Column("priority", sa.Integer(), nullable=True),
        sa.Column("flags", sa.JSON(), nullable=True),
        sa.Column("trust_score", sa.Float(), nullable=True),
        sa.Column("classification", sa.String(), nullable=True),
        sa.Column("data_source_id", sa.String(), nullable=True),
        sa.Column("source_ip", sa.String(), nullable=True),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("public_key", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("verified_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["data_source_id"], ["data_sources.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_context_records_content_hash"), "context_records", ["content_hash"], unique=False)
    op.create_index(op.f("ix_context_records_created_at"), "context_records", ["created_at"], unique=False)
    op.create_index(op.f("ix_context_records_session_id"), "context_records", ["session_id"], unique=False)
    op.create_index(op.f("ix_context_records_user_id"), "context_records", ["user_id"], unique=False)

    op.create_table(
        "hash_records",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("context_id", sa.String(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("hash_value", sa.String(), nullable=False),
        sa.Column("previous_hash", sa.String(), nullable=True),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["context_id"], ["context_records.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_hash_records_context_id"), "hash_records", ["context_id"], unique=False)
    op.create_index(op.f("ix_hash_records_hash_value"), "hash_records", ["hash_value"], unique=False)

    op.create_table(
        "signature_records",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("context_id", sa.String(), nullable=False),
        sa.Column("algorithm", sa.String(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("public_key", sa.String(), nullable=False),
        sa.Column("is_valid", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["context_id"], ["context_records.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_signature_records_context_id"), "signature_records", ["context_id"], unique=False)

    op.create_table(
        "verification_results",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("context_id", sa.String(), nullable=False),
        sa.Column("trust_score", sa.Float(), nullable=False),
        sa.Column("classification", sa.String(), nullable=False),
        sa.Column("is_valid", sa.Boolean(), nullable=False),
        sa.Column("tampering_detected", sa.Boolean(), nullable=True),
        sa.Column("replay_attack_detected", sa.Boolean(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["context_id"], ["context_records.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_verification_results_context_id"), "verification_results", ["context_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_verification_results_context_id"), table_name="verification_results")
    op.drop_table("verification_results")

    op.drop_index(op.f("ix_signature_records_context_id"), table_name="signature_records")
    op.drop_table("signature_records")

    op.drop_index(op.f("ix_hash_records_hash_value"), table_name="hash_records")
    op.drop_index(op.f("ix_hash_records_context_id"), table_name="hash_records")
    op.drop_table("hash_records")

    op.drop_index(op.f("ix_context_records_user_id"), table_name="context_records")
    op.drop_index(op.f("ix_context_records_session_id"), table_name="context_records")
    op.drop_index(op.f("ix_context_records_created_at"), table_name="context_records")
    op.drop_index(op.f("ix_context_records_content_hash"), table_name="context_records")
    op.drop_table("context_records")

    op.drop_index(op.f("ix_data_sources_user_id"), table_name="data_sources")
    op.drop_table("data_sources")

    op.drop_index(op.f("ix_audit_logs_user_id"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_resource_id"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_created_at"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_action"), table_name="audit_logs")
    op.drop_table("audit_logs")

    op.drop_index(op.f("ix_users_username"), table_name="users")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_table("users")

    op.drop_index(op.f("ix_security_events_user_id"), table_name="security_events")
    op.drop_index(op.f("ix_security_events_event_type"), table_name="security_events")
    op.drop_index(op.f("ix_security_events_created_at"), table_name="security_events")
    op.drop_index(op.f("ix_security_events_context_id"), table_name="security_events")
    op.drop_table("security_events")

    op.drop_table("certificates")
