# -*- coding: utf-8 -*-

from flask_login import UserMixin
from . import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    password = db.Column(db.String(50))
    name = db.Column(db.String(30), unique=True)
    
class Public_notes(db.Model):
    id = db.Column(db.Integer, primary_key=True) 
    name = db.Column(db.String(30))
    note = db.Column(db.String(200))
    
class Private_notes(db.Model):
    id = db.Column(db.Integer, primary_key=True) 
    name = db.Column(db.String(30))
    note = db.Column(db.String(200))