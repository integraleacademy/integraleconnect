from datetime import datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class TimestampMixin:
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Tenant(TimestampMixin, db.Model):
    __tablename__ = "tenants"

    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(180), nullable=False)
    siret = db.Column(db.String(14), nullable=False, unique=True)
    contact_name = db.Column(db.String(180), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    users = db.relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    module_access = db.relationship("ModuleAccess", back_populates="tenant", uselist=False, cascade="all, delete-orphan")


class User(UserMixin, TimestampMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    tenant = db.relationship("Tenant", back_populates="users")

    def get_id(self):
        return str(self.id)


class ModuleAccess(TimestampMixin, db.Model):
    __tablename__ = "module_access"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False, unique=True)
    module_crm = db.Column(db.Boolean, default=False, nullable=False)
    module_partenaires = db.Column(db.Boolean, default=False, nullable=False)
    module_cpf = db.Column(db.Boolean, default=False, nullable=False)

    tenant = db.relationship("Tenant", back_populates="module_access")
