from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    name: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
    )

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    memberships: Mapped[list["Membership"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )

    analyses: Mapped[list["Analysis"]] = relationship(
        back_populates="user",
        foreign_keys="Analysis.user_id",
    )

    audit_events: Mapped[list["AuditEvent"]] = relationship(
        back_populates="user",
    )


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    name: Mapped[str] = mapped_column(
        String(180),
        nullable=False,
    )

    slug: Mapped[str] = mapped_column(
        String(120),
        unique=True,
        index=True,
        nullable=False,
    )

    plan: Mapped[str] = mapped_column(
        String(40),
        default="small_business",
        nullable=False,
    )

    subscription_status: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    stripe_customer_id: Mapped[str | None] = mapped_column(
        String(120),
        nullable=True,
    )

    stripe_subscription_id: Mapped[str | None] = mapped_column(
        String(120),
        nullable=True,
    )

    stripe_price_id: Mapped[str | None] = mapped_column(
        String(120),
        nullable=True,
    )

    subscription_cancel_at_period_end: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    subscription_current_period_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    memberships: Mapped[list["Membership"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
    )

    environments: Mapped[list["Environment"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
    )

    analyses: Mapped[list["Analysis"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
    )

    audit_events: Mapped[list["AuditEvent"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
    )

    governance_policy: Mapped["GovernancePolicy | None"] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
        uselist=False,
    )

class GovernancePolicy(Base):
    __tablename__ = "governance_policies"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id"),
        unique=True,
        nullable=False,
        index=True,
    )

    high_risk_review_required: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    caution_review_required: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    review_deadline_days: Mapped[int] = mapped_column(
        Integer,
        default=7,
        nullable=False,
    )

    resolution_note_required: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    organization: Mapped["Organization"] = relationship(
        back_populates="governance_policy",
    )


class Membership(Base):
    __tablename__ = "memberships"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    role: Mapped[str] = mapped_column(
        String(30),
        default="viewer",
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    user: Mapped["User"] = relationship(
        back_populates="memberships",
    )

    organization: Mapped["Organization"] = relationship(
        back_populates="memberships",
    )

class TeamInvitation(Base):
    __tablename__ = "team_invitations"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    invited_by_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    role: Mapped[str] = mapped_column(
        String(30),
        default="viewer",
        nullable=False,
    )

    token: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="pending",
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    delivery_status: Mapped[str] = mapped_column(
        String(30),
        default="pending",
        nullable=False,
    )

    last_delivery_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

class Environment(Base):
    __tablename__ = "environments"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    organization: Mapped["Organization"] = relationship(
        back_populates="environments",
    )


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    environment_id: Mapped[int | None] = mapped_column(
        ForeignKey("environments.id"),
        nullable=True,
        index=True,
    )

    source: Mapped[str | None] = mapped_column(
        String(80),
        nullable=True,
    )

    filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    extension: Mapped[str | None] = mapped_column(
        String(40),
        nullable=True,
    )

    mime_type: Mapped[str | None] = mapped_column(
        String(120),
        nullable=True,
    )

    file_size: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    virustotal_found: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )

    virustotal_malicious: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    virustotal_suspicious: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    virustotal_undetected: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    virustotal_harmless: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    virustotal_error: Mapped[str | None] = mapped_column(
        String(80),
        nullable=True,
    )

    risk_level: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    decision: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    review_status: Mapped[str] = mapped_column(
        String(30),
        default="open",
        nullable=False,
    )

    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    reviewed_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
    )

    resolution_note: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    explanation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    reasons: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    organization: Mapped["Organization"] = relationship(
        back_populates="analyses",
    )

    user: Mapped["User"] = relationship(
        back_populates="analyses",
        foreign_keys=[user_id],
    )

    environment: Mapped["Environment | None"] = relationship()


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(80),
        nullable=False,
        index=True,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    metadata_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
        index=True,
    )

    organization: Mapped["Organization"] = relationship(
        back_populates="audit_events",
    )

    user: Mapped["User | None"] = relationship(
        back_populates="audit_events",
    )


class Invitation(Base):
    __tablename__ = "invitations"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    role: Mapped[str] = mapped_column(
        String(30),
        default="viewer",
        nullable=False,
    )

    token: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
    )

    accepted: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )


class BillingRequest(Base):
    __tablename__ = "billing_requests"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"),
        nullable=True,
        index=True,
    )

    company_name: Mapped[str] = mapped_column(
        String(180),
        nullable=False,
    )

    contact_name: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
    )

    contact_email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    estimated_users: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    estimated_monthly_files: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    purchase_order: Mapped[str | None] = mapped_column(
        String(120),
        nullable=True,
    )

    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(40),
        default="pending",
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

class SupportRequest(Base):
    __tablename__ = "support_requests"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"),
        nullable=True,
        index=True,
    )

    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    request_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    subject: Mapped[str] = mapped_column(
        String(180),
        nullable=False,
    )

    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(40),
        default="open",
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

class PendingPurchase(Base):
    __tablename__ = "pending_purchases"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    token: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )

    plan: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
    )

    billing_interval: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="pending",
        nullable=False,
    )

    stripe_checkout_session_id: Mapped[str | None] = mapped_column(
        String(120),
        nullable=True,
    )

    stripe_customer_id: Mapped[str | None] = mapped_column(
        String(120),
        nullable=True,
    )

    stripe_subscription_id: Mapped[str | None] = mapped_column(
        String(120),
        nullable=True,
    )

    stripe_price_id: Mapped[str | None] = mapped_column(
        String(120),
        nullable=True,
    )

    customer_email: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )