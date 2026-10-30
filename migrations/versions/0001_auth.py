"""auth: usuarios, sesiones, tokens, MFA, OAuth, intentos, consentimientos y eventos

Revision ID: 0001_auth
Revises: (ninguna)
Create Date: 2026-10-29 23:21:12.976380

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# Identificadores de la revisión, usados por Alembic.
revision: str = "0001_auth"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Aplica la migración."""
    op.create_table(
        "login_attempts",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_login_attempts")),
    )
    op.create_index(
        "ix_login_attempts_key_kind_created_at",
        "login_attempts",
        ["key", "kind", "created_at"],
        unique=False,
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("email = lower(btrim(email))", name=op.f("ck_users_email_normalized")),
        sa.CheckConstraint(
            "name = btrim(name) AND char_length(name) BETWEEN 1 AND 100",
            name=op.f("ck_users_name_length"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
    )
    op.create_index(
        "uq_users_email_lower", "users", [sa.literal_column("lower(email)")], unique=True
    )
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("stage", sa.Text(), nullable=False),
        sa.Column("csrf_token", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reauthenticated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("pending_google_subject", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "(stage = 'link_pending') = (pending_google_subject IS NOT NULL)",
            name=op.f("ck_auth_sessions_pending_google_subject"),
        ),
        sa.CheckConstraint(
            "stage IN ('active', 'mfa_pending', 'link_pending')",
            name=op.f("ck_auth_sessions_stage"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_auth_sessions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_auth_sessions")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_auth_sessions_token_hash")),
    )
    op.create_index(op.f("ix_auth_sessions_user_id"), "auth_sessions", ["user_id"], unique=False)
    op.create_table(
        "auth_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "purpose IN ('verify_email', 'reset_password')", name=op.f("ck_auth_tokens_purpose")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_auth_tokens_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_auth_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_auth_tokens_token_hash")),
    )
    op.create_index(
        "ix_auth_tokens_user_id_purpose", "auth_tokens", ["user_id", "purpose"], unique=False
    )
    op.create_table(
        "data_consents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("policy_version", sa.Text(), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_data_consents_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_data_consents")),
    )
    op.create_index(op.f("ix_data_consents_user_id"), "data_consents", ["user_id"], unique=False)
    op.create_table(
        "external_identities",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("provider IN ('google')", name=op.f("ck_external_identities_provider")),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_external_identities_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_external_identities")),
        sa.UniqueConstraint("provider", "subject", name="uq_external_identities_provider_subject"),
    )
    op.create_index(
        op.f("ix_external_identities_user_id"), "external_identities", ["user_id"], unique=False
    )
    op.create_table(
        "mfa_credentials",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("secret_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_step", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_mfa_credentials_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("user_id", name=op.f("pk_mfa_credentials")),
    )
    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("code_hash", sa.Text(), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_mfa_recovery_codes_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mfa_recovery_codes")),
    )
    op.create_index(
        op.f("ix_mfa_recovery_codes_user_id"), "mfa_recovery_codes", ["user_id"], unique=False
    )
    op.create_table(
        "security_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("ip", postgresql.INET(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_security_events_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_events")),
    )
    op.create_index(
        op.f("ix_security_events_created_at"), "security_events", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_security_events_user_id"), "security_events", ["user_id"], unique=False
    )
    op.create_table(
        "oauth_flows",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("state_hash", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.Text(), nullable=False),
        sa.Column("code_verifier", sa.Text(), nullable=False),
        sa.Column("intent", sa.Text(), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("intent IN ('login', 'reauth')", name=op.f("ck_oauth_flows_intent")),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["auth_sessions.id"],
            name=op.f("fk_oauth_flows_session_id_auth_sessions"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_oauth_flows")),
        sa.UniqueConstraint("state_hash", name=op.f("uq_oauth_flows_state_hash")),
    )
    op.create_index(op.f("ix_oauth_flows_session_id"), "oauth_flows", ["session_id"], unique=False)


def downgrade() -> None:
    """Revierte la migración."""
    op.drop_index(op.f("ix_oauth_flows_session_id"), table_name="oauth_flows")
    op.drop_table("oauth_flows")
    op.drop_index(op.f("ix_security_events_user_id"), table_name="security_events")
    op.drop_index(op.f("ix_security_events_created_at"), table_name="security_events")
    op.drop_table("security_events")
    op.drop_index(op.f("ix_mfa_recovery_codes_user_id"), table_name="mfa_recovery_codes")
    op.drop_table("mfa_recovery_codes")
    op.drop_table("mfa_credentials")
    op.drop_index(op.f("ix_external_identities_user_id"), table_name="external_identities")
    op.drop_table("external_identities")
    op.drop_index(op.f("ix_data_consents_user_id"), table_name="data_consents")
    op.drop_table("data_consents")
    op.drop_index("ix_auth_tokens_user_id_purpose", table_name="auth_tokens")
    op.drop_table("auth_tokens")
    op.drop_index(op.f("ix_auth_sessions_user_id"), table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_index("uq_users_email_lower", table_name="users")
    op.drop_table("users")
    op.drop_index("ix_login_attempts_key_kind_created_at", table_name="login_attempts")
    op.drop_table("login_attempts")
