"""Datenbankmodell (SQLAlchemy, SQLite)."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Naive UTC-Zeit (SQLite speichert keine Zeitzonen)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class DomainList(Base):
    __tablename__ = "domain_lists"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    # Eine Domain pro Zeile, bereits geprüft und normalisiert.
    domains: Mapped[str] = mapped_column(Text, default="")

    services: Mapped[list["Service"]] = relationship(back_populates="domain_list")

    @property
    def domain_items(self) -> list[str]:
        return [d for d in self.domains.split("\n") if d]


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Direkte Domains (eine pro Zeile) – leer, wenn eine Domainliste benutzt wird.
    domains: Mapped[str] = mapped_column(Text, default="")
    domain_list_id: Mapped[int | None] = mapped_column(
        ForeignKey("domain_lists.id", ondelete="RESTRICT"), nullable=True
    )
    target_ip: Mapped[str] = mapped_column(String(15))
    http_port: Mapped[int] = mapped_column(Integer, default=80)
    http_proxy: Mapped[str] = mapped_column(String(3), default="off")
    https_port: Mapped[int] = mapped_column(Integer, default=443)
    https_proxy: Mapped[str] = mapped_column(String(3), default="off")
    redirect_to_https: Mapped[bool] = mapped_column(Boolean, default=False)
    health_check: Mapped[bool] = mapped_column(Boolean, default=False)

    domain_list: Mapped[DomainList | None] = relationship(back_populates="services")

    @property
    def domain_items(self) -> list[str]:
        return [d for d in self.domains.split("\n") if d]

    @property
    def effective_domains(self) -> list[str]:
        if self.domain_list is not None:
            return self.domain_list.domain_items
        return self.domain_items


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


class Version(Base):
    """Eine angewendete Fassung der Konfiguration."""

    __tablename__ = "versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    description: Mapped[str] = mapped_column(Text, default="")
    cfg_text: Mapped[str] = mapped_column(Text)
    lists_json: Mapped[str] = mapped_column(Text)  # {name: dateitext}
    state_json: Mapped[str] = mapped_column(Text)  # Datenstand, siehe state.py


class Admin(Base):
    __tablename__ = "admin"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64))
    password_hash: Mapped[str] = mapped_column(Text)


class AuthSession(Base):
    __tablename__ = "sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    last_failure: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
