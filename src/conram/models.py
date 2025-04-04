from flask_security import UserMixin, RoleMixin
import uuid
from sqlalchemy import Column, String, Integer, DateTime
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()


class Asset(db.Model):
    __tablename__ = 'assets'

    id = Column(String, primary_key=True)
    asset_type = Column(String, nullable=False)
    asset_status = Column(String, nullable=False)
    db.UniqueConstraint('id', name='asset_id')


class Staff(db.Model):
    __tablename__ = 'staffs'

    id = Column(String, primary_key=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    division = Column(String, nullable=False)
    department = Column(String, nullable=False)
    title = Column(String, nullable=False)


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
    __table_args__ = (
        db.UniqueConstraint('settingid', name='setting_id'),
    )


roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'))
)

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(150), unique=True, nullable=False)
    password = Column(String(150), nullable=False, server_default='')
    staff_id = db.Column(String, db.ForeignKey('staffs.id'), nullable=True, unique=True)
    email = Column(String(150), unique=True, nullable=False)
    active = Column(db.Boolean(), default=True)
    confirmed_at = Column(DateTime())
    fs_uniquifier = Column(String(150), unique=True,
                           nullable=False, default=lambda: str(uuid.uuid4()))
    roles = db.relationship('Role', secondary=roles_users,
                            backref='roled')
    last_login = Column(DateTime, nullable=True)

class Role(db.Model, RoleMixin):
    __tablename__ = 'roles'
    id = Column(Integer(), primary_key=True)
    name = Column(String(80), unique=True, nullable=False)
    description = Column(String(255))
