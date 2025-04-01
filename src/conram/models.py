from flask_security import UserMixin, RoleMixin
import uuid
from sqlalchemy import Column, String, Integer, DateTime
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()


roles_users = db.Table(
    'roles_users',
    db.Column('staff_id', db.String, db.ForeignKey('staffs.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'))
)


class Asset(db.Model):
    __tablename__ = 'assets'

    id = Column(String, primary_key=True)
    asset_type = Column(String, nullable=False)
    asset_status = Column(String, nullable=False)
    db.UniqueConstraint('id', name='asset_id')


class Staff(db.Model, UserMixin):
    __tablename__ = 'staffs'

    id = Column(String, primary_key=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    division = Column(String, nullable=False)
    department = Column(String, nullable=False)
    title = Column(String, nullable=False)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)
    is_active = Column(db.Boolean(), default=False)
    fs_uniquifier = Column(String(150), unique=True,
                           nullable=False, default=lambda: str(uuid.uuid4()))
    last_login = Column(DateTime, nullable=True)
    roles = db.relationship('Role', secondary=roles_users,
                            backref='staffed')


class Checkout(db.Model):
    __tablename__ = 'checkouts'

    assetid = Column(String, nullable=False, primary_key=True)
    staffid = Column(String, nullable=False)
    department = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    db.UniqueConstraint('assetid', name='check_a_id')


class History(db.Model):
    __tablename__ = 'history'
    id = Column(Integer, primary_key=True, autoincrement=True)
    assetid = Column(String, nullable=False)
    staffid = Column(String, nullable=False)
    department = Column(String, nullable=False)
    division = Column(String, nullable=False)
    checkouttime = Column(DateTime, nullable=False)
    returntime = Column(DateTime, nullable=False)


class GlobalSet(db.Model):
    __tablename__ = 'globalset'

    settingid = Column(String, primary_key=True)
    setting = Column(String, nullable=False)
    db.UniqueConstraint('settingid', name='setting_id')


class Role(db.Model, RoleMixin):
    __tablename__ = 'roles'
    id = Column(Integer(), primary_key=True)
    name = Column(String(80), unique=True, nullable=False)
    description = Column(String(255))
