import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
from flask_login import UserMixin


Base = declarative_base()


class User(Base, UserMixin):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True, unique=True)
    hash_password = Column(String(80))
    UniqueConstraint('username')

    def hashed_password(self, password):
        self.hash_password = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.hash_password)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.id)

    @property
    def serializable(self):
        return {'id': self.id, 'username': self.username}


class Catalog(Base):
    __tablename__ = 'catalog'
    id = Column(Integer, primary_key=True)
    name = Column(String(32), nullable=False)

    @property
    def serializable(self):

        return {'id': self.id, 'name': self.name}


class Item(Base):
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    name = Column(String(32), nullable=False)
    description = Column(String(255))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    catalog_id = Column(Integer, ForeignKey('catalog.id'))
    catalog = relationship(Catalog, backref='items')

    @property
    def serializable(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'catalog_id': self.catalog_id,
            'user_id': self.user_id
        }


engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)
