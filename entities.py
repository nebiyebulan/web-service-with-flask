import json
from base64 import b64decode

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os
from datetime import datetime, timedelta
import datetime
import jwt
from functools import wraps
from DatabaseConnect import db, app, ma

class MyDateTime(db.TypeDecorator):
    impl = db.DateTime

    def process_bind_param(self, value, dialect):
        if type(value) is str:
            return datetime.strptime(value, '%Y-%m-%dT%H:%M:%S')
        return value


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    phonenumber = db.Column(db.String(50))
    isactive = db.Column(db.Boolean())
    isdeleted = db.Column(db.Boolean())
    userroleid = db.Column(db.Integer, db.ForeignKey('userroles.id'), nullable=False)
    modifieddate = db.Column(db.DateTime)
    createddate = db.Column(db.DateTime)
    vehicles = db.relationship('Vehicles', backref='users')

    def __init__(self, email, password, username, phonenumber, isactive, isdeleted,
                 userroleid, modifieddate=None, createddate=None):
        self.email = email
        self.password = password
        self.username = username
        self.phonenumber = phonenumber
        self.isactive = isactive
        self.isdeleted = isdeleted
        self.userroleid = userroleid
        self.modifieddate = (modifieddate if modifieddate else datetime.datetime.utcnow() + timedelta(hours=3))
        self.createddate = (createddate if createddate else datetime.datetime.utcnow() + timedelta(hours=3))


# create user_role
class Userroles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rolename = db.Column(db.String(50), nullable=False)
    isactive = db.Column(db.Boolean(), nullable=False)
    isdeleted = db.Column(db.Boolean(), nullable=False)
    modifieddate = db.Column(db.DateTime)
    createddate = db.Column(db.DateTime)
    role = db.relationship('Users', backref='userroles', uselist=False)

    def __init__(self, rolename, isactive, isdeleted, modifieddate=None, createddate=None):
        self.rolename = rolename
        self.isactive = isactive
        self.isdeleted = isdeleted
        self.modifieddate = (modifieddate if modifieddate else datetime.datetime.utcnow() + timedelta(hours=3))
        self.createddate = (createddate if createddate else datetime.datetime.utcnow() + timedelta(hours=3))

class RoleSchema(ma.Schema):
    class Meta:
        fields = ('id', 'rolename', 'isactive','isdeleted', 'modifieddate', 'createddate')

role_schema = RoleSchema()
roles_schema = RoleSchema(many=True)

class UserSchema(ma.Schema):
    class Meta:
        fields = (
            'id', 'email', 'password', 'username', 'phonenumber', 'isactive', 'isdeleted', 'userroleid', 'modifieddate', 'createddate', 'userroles.rolename')

user_schema = UserSchema()
users_schema = UserSchema(many=True)

# create vehicles
class Vehicles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    licenceplate = db.Column(db.String(9), unique=True, nullable=False)
    brand = db.Column(db.String(50))
    model = db.Column(db.String(50))
    year = db.Column(db.Integer)
    isguest = db.Column(db.Boolean(), nullable=False)
    isactive = db.Column(db.Boolean(), nullable=False)
    isdeleted = db.Column(db.Boolean(), nullable=False)
    vehicletypeid = db.Column(db.Integer, db.ForeignKey('vehicletypes.id'), nullable=False)
    userid = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    modifieddate = db.Column(db.DateTime)
    createddate = db.Column(db.DateTime)
    logins = db.relationship('Vehiclelogins', backref='vehicles')

    def __init__(self, licenceplate, brand, model, year, isguest, isactive, isdeleted, vehicletypeid, userid, modifieddate=None, createddate=None):
        self.licenceplate = licenceplate
        self.brand = brand
        self.model = model
        self.year = year
        self.isguest = isguest
        self.isactive = isactive
        self.isdeleted = isdeleted
        self.vehicletypeid = vehicletypeid
        self.userid = userid
        self.modifieddate = (modifieddate if modifieddate else datetime.datetime.utcnow() + timedelta(hours=3))
        self.createddate = (createddate if createddate else datetime.datetime.utcnow() + timedelta(hours=3))

class VehicleSchema(ma.Schema):
    class Meta:
        fields = ('id', 'licenceplate', 'brand', 'model', 'year', 'isguest', 'isactive',
                  'isdeleted', 'vehicletypeid', 'userid', 'modifieddate', 'createddate',  'users.username', 'users.phonenumber',
                  'vehicletypes.typename')

vehicle_schema = VehicleSchema()
vehicles_schema = VehicleSchema(many=True)

class Vehicletypes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    typename = db.Column(db.String(50), nullable=False)
    isactive = db.Column(db.Boolean(), nullable=False)
    isdeleted = db.Column(db.Boolean(), nullable=False)
    modifieddate = db.Column(db.DateTime)
    createddate = db.Column(db.DateTime)
    vehicle = db.relationship('Vehicles', backref='vehicletypes', uselist=False)

    def __init__(self, typename, isactive, isdeleted, modifieddate=None, createddate=None):
        self.typename = typename
        self.isactive = isactive
        self.isdeleted = isdeleted
        self.modifieddate = (modifieddate if modifieddate else datetime.datetime.utcnow() + timedelta(hours=3))
        self.createddate = (createddate if createddate else datetime.datetime.utcnow() + timedelta(hours=3))

class VehicletypeSchema(ma.Schema):
    class Meta:
        fields = ('id', 'typename', 'isactive', 'isdeleted', 'modifieddate', 'createddate')


vehicletype_schema = VehicletypeSchema()
vehicletypes_schema = VehicletypeSchema(many=True)


class Vehiclelogins(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    isactive = db.Column(db.Boolean(), nullable=False)
    isdeleted = db.Column(db.Boolean(), nullable=False)
    vehicleid = db.Column(db.Integer, db.ForeignKey('vehicles.id'), nullable=False)
    logintypeid = db.Column(db.Integer, db.ForeignKey('logintypes.id'), nullable=False)
    processdate = db.Column(db.DateTime)
    modifieddate = db.Column(db.DateTime)
    createddate = db.Column(db.DateTime)

    def __init__(self, isactive, isdeleted, vehicleid, logintypeid, processdate=None, modifieddate=None, createddate=None):
        self.isactive = isactive
        self.isdeleted = isdeleted
        self.vehicleid = vehicleid
        self.logintypeid = logintypeid
        self.processdate = (processdate if processdate else datetime.datetime.utcnow() + timedelta(hours=3))
        self.modifieddate = (modifieddate if modifieddate else datetime.datetime.utcnow() + timedelta(hours=3))
        self.createddate = (createddate if createddate else datetime.datetime.utcnow() + timedelta(hours=3))

class LoginSchema(ma.Schema):
    class Meta:
        fields = (
            'id', 'isactive', 'isdeleted', 'vehicleid', 'logintypeid','processdate', 'modifieddate', 'createddate'
            'vehicles.licenceplate', 'vehicles.isguest', 'vehicles.brand', 'vehicles.model', 'vehicles.year')


login_schema = LoginSchema()
logins_schema = LoginSchema(many=True)

class Logintypes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    typename = db.Column(db.String(50), nullable=False)
    isactive = db.Column(db.Boolean(), nullable=False)
    isdeleted = db.Column(db.Boolean(), nullable=False)
    modifieddate = db.Column(db.DateTime)
    createddate = db.Column(db.DateTime)
    logintyp = db.relationship('Vehiclelogins', backref='logintypes')

    def __init__(self, typename, isactive, isdeleted, modifieddate=None, createddate=None):
        self.typename = typename
        self.isactive = isactive
        self.isdeleted = isdeleted
        self.modifieddate = (createddate if createddate else datetime.datetime.utcnow() + timedelta(hours=3))
        self.createddate = (createddate if createddate else datetime.datetime.utcnow() + timedelta(hours=3))

class LogintypeSchema(ma.Schema):
    class Meta:
        fields = ('id', 'typename', 'isactive', 'isdeleted', 'modifieddate', 'createddate')

logintype_schema = LogintypeSchema()
logintypes_schema = LogintypeSchema(many=True)

if __name__ == '__main__':
    app.run(debug=True)
