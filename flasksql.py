from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your secret key'
basedir = os.path.abspath(os.path.dirname(__file__))
# database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)
ma = Marshmallow(app)

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
    isactive = db.Column(db.Boolean(), nullable=False)
    createddate = db.Column(MyDateTime, default=datetime.now, nullable=False)
    modifieddate = db.Column(MyDateTime, default=datetime.now, nullable=False)
    isdeleted = db.Column(db.Boolean(), nullable=False)
    userroleid = db.Column(db.Integer, db.ForeignKey('userroles.id'), nullable=False)

    vehicles = db.relationship('Vehicles', backref='users')

    def __init__(self, email, password, username, phonenumber, isactive, createddate, modifieddate, isdeleted,
                 userroleid):
        self.email = email
        self.password = password
        self.username = username
        self.phonenumber = phonenumber
        self.isactive = isactive
        self.createddate = createddate
        self.modifieddate = modifieddate
        self.isdeleted = isdeleted
        self.userroleid = userroleid


# create user_role
class Userroles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rolename = db.Column(db.String(50), nullable=False)
    isactive = db.Column(db.Boolean(), nullable=False)
    createddate = db.Column(MyDateTime, default=datetime.now, nullable=False)
    modifieddate = db.Column(MyDateTime, default=datetime.now, nullable=False)
    isdeleted = db.Column(db.Boolean(), nullable=False)
    role = db.relationship('Users', backref='userroles', uselist=False)

    def __init__(self, rolename, isactive, createddate, modifieddate, isdeleted):
        self.rolename = rolename
        self.isactive = isactive
        self.createddate = createddate
        self.modifieddate = modifieddate
        self.isdeleted = isdeleted


class RoleSchema(ma.Schema):
    class Meta:
        fields = ('id', 'rolename', 'isactive', 'createddate', 'modifieddate', 'isdeleted')

role_schema = RoleSchema()
roles_schema = RoleSchema(many=True)

class UserSchema(ma.Schema):
    class Meta:
        fields = (
        'id', 'email', 'password', 'username', 'phonenumber', 'isactive', 'createddate', 'modifieddate', 'isdeleted',
        'userroleid', 'userroles.rolename')

user_schema = UserSchema()
users_schema = UserSchema(many=True)

# create vehicles
class Vehicles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    licenceplate = db.Column(db.String(50), unique=True, nullable=False)
    brand = db.Column(db.String(50))
    model = db.Column(db.String(50))
    year = db.Column(db.Integer())
    isguest = db.Column(db.Boolean(), nullable=False)
    isactive = db.Column(db.Boolean(), nullable=False)
    createddate = db.Column(MyDateTime, default=datetime.now, nullable=False)
    modifieddate = db.Column(MyDateTime, default=datetime.now, nullable=False)
    isdeleted = db.Column(db.Boolean(), nullable=False)
    vehicletypeid = db.Column(db.Integer, db.ForeignKey('vehicletypes.id'), nullable=False)
    logins = db.relationship('Vehiclelogins', backref='vehicles')
    userid = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __init__(self, licenceplate, brand, model, year, isguest, isactive, createddate, modifieddate, isdeleted, vehicletypeid, userid):
        self.licenceplate = licenceplate
        self.brand = brand
        self.model = model
        self.year = year
        self.isguest = isguest
        self.isactive = isactive
        self.createddate = createddate
        self.modifieddate = modifieddate
        self.isdeleted = isdeleted
        self.vehicletypeid = vehicletypeid
        self.userid = userid

class VehicleSchema(ma.Schema):
    class Meta:
        fields = ('id', 'licenceplate', 'brand', 'model', 'year', 'isguest', 'isactive', 'createddate', 'modifieddate',
                  'isdeleted', 'vehicletypeid', 'userid', 'users.username', 'users.phonenumber',
                  'vehicletypes.typename')

vehicle_schema = VehicleSchema()
vehicles_schema = VehicleSchema(many=True)

class Vehicletypes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    typename = db.Column(db.String(50), nullable=False)
    isactive = db.Column(db.Boolean(), nullable=False)
    createddate = db.Column(MyDateTime, default=datetime.now, nullable=False)
    modifieddate = db.Column(MyDateTime, default=datetime.now, nullable=False)
    isdeleted = db.Column(db.Boolean(), nullable=False)
    vehicle = db.relationship('Vehicles', backref='vehicletypes', uselist=False)

    def __init__(self, typename, isactive, createddate, modifieddate, isdeleted):
        self.typename = typename
        self.isactive = isactive
        self.createddate = createddate
        self.modifieddate = modifieddate
        self.isdeleted = isdeleted

class VehicletypeSchema(ma.Schema):
    class Meta:
        fields = ('id', 'typename', 'isactive', 'createddate', 'modifieddate', 'isdeleted')

vehicletype_schema = VehicletypeSchema()
vehicletypes_schema = VehicletypeSchema(many=True)

class Vehiclelogins(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    processdate = db.Column(MyDateTime, default=datetime.now, nullable=False)
    isactive = db.Column(db.Boolean(), nullable=False)
    createddate = db.Column(MyDateTime, default=datetime.now, nullable=False)
    modifieddate = db.Column(MyDateTime, default=datetime.now, nullable=False)
    isdeleted = db.Column(db.Boolean(), nullable=False)
    vehicleid = db.Column(db.Integer, db.ForeignKey('vehicles.id'), nullable=False)
    logintypeid = db.Column(db.Integer, db.ForeignKey('logintypes.id'), nullable=False)

    def __init__(self, processdate, isactive, createddate, modifieddate, isdeleted, vehicleid, logintypeid):
        self.processdate = processdate
        self.isactive = isactive
        self.createddate = createddate
        self.modifieddate = modifieddate
        self.isdeleted = isdeleted
        self.vehicleid = vehicleid
        self.logintypeid = logintypeid

class LoginSchema(ma.Schema):
    class Meta:
        fields = (
        'id', 'processdate', 'isactive', 'createddate', 'modifieddate', 'isdeleted', 'vehicleid', 'logintypeid',
        'vehicles.licenceplate', 'vehicles.isguest', 'vehicles.brand', 'vehicles.model', 'vehicles.year')

login_schema = LoginSchema()
logins_schema = LoginSchema(many=True)

class Logintypes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    typename = db.Column(db.String(50), nullable=False)
    isactive = db.Column(db.Boolean(), nullable=False)
    createddate = db.Column(MyDateTime, default=datetime.now, nullable=False)
    modifieddate = db.Column(MyDateTime, default=datetime.now, nullable=False)
    isdeleted = db.Column(db.Boolean(), nullable=False)
    logintyp = db.relationship('Vehiclelogins', backref='logintypes')

    def __init__(self, typename, isactive, createddate, modifieddate, isdeleted):
        self.typename = typename
        self.isactive = isactive
        self.createddate = createddate
        self.modifieddate = modifieddate
        self.isdeleted = isdeleted

class LogintypeSchema(ma.Schema):
    class Meta:
        fields = ('id', 'typename', 'isactive', 'createddate', 'modifieddate', 'isdeleted')

logintype_schema = LogintypeSchema()
logintypes_schema = LogintypeSchema(many=True)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_vehicle = Vehicles.query \
                .filter_by(id=data['id']) \
                .first()
        except:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        return f(current_vehicle, *args, **kwargs)

    return decorated

@app.route('/User/Register', methods=['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.json

    # gets name, email and password
    username, email, phonenumber, createddate, modifieddate, isdeleted, isactive, userroleid = data.get(
        'username'), data.get('email'), data.get('phonenumber'), data.get('createddate'), data.get(
        'modifieddate'), data.get('isactive'), data.get('isdeleted'), data.get('userroleid')
    password = data.get('password')

    # checking for existing user
    user = Users.query \
        .filter_by(email=email) \
        .first()
    if not user:
        # database ORM object
        user = Users(
            username=username,
            email=email,
            password=generate_password_hash(password),
            phonenumber=phonenumber,
            createddate=createddate,
            modifieddate=modifieddate,
            isactive=isactive,
            isdeleted=isdeleted,
            userroleid=userroleid,
        )
        # insert user
        db.session.add(user)
        db.session.commit()

        return make_response('Successfully registered.', 200)
    else:
        # returns 202 if user already exists
        return make_response('User already exists.', 202)

# get all users
@app.route('/User/GetAll', methods=['GET'])
def get_users():
    all_users = Users.query.all()
    result = users_schema.dump(all_users)
    print(result)
    return jsonify(result)


# get single users
@app.route('/User/Get/<id>', methods=['GET'])
def get_user(id):
    user = Users.query.get(id)
    return user_schema.jsonify(user)


# update users
@app.route('/User/Update/<id>', methods=['PUT'])
def update_users(id):
    user = Users.query.get(id)
    email = request.json['email']
    password = request.json['password']
    username = request.json['username']
    phonenumber = request.json['phonenumber']
    isactive = request.json['isactive']
    createddate = request.json['createddate']
    modifieddate = request.json['modifieddate']
    isdeleted = request.json['isdeleted']
    userroleid = request.json['userroleid']

    user.email = email
    user.password = password
    user.username = username
    user.phonenumber = phonenumber
    user.isactive = isactive
    user.createddate = createddate
    user.modifieddate = modifieddate
    user.isdeleted = isdeleted
    user.userroleid = userroleid

    db.session.commit()
    return user_schema.jsonify(user)


# delete users
@app.route('/User/Delete/<id>', methods=['DELETE'])
def delete_users(id):
    user = Users.query.get(id)
    db.session.delete(user)
    db.session.commit()
    return user_schema.jsonify(user)

# for role
@app.route('/UserRole/Register', methods=['POST'])
def add_role():
    rolename = request.json['rolename']
    isactive = request.json['isactive']
    createddate = request.json['createddate']
    modifieddate = request.json['modifieddate']
    isdeleted = request.json['isdeleted']

    new_role = Userroles(rolename, isactive, createddate, modifieddate, isdeleted)

    db.session.add(new_role)
    db.session.commit()
    return role_schema.jsonify(new_role)

# get all role
@app.route('/UserRoles/GetAll', methods=['GET'])
def get_roles():
    all_roles = Userroles.query.all()
    result = roles_schema.dump(all_roles)
    return jsonify(result)

# get single role
@app.route('/UserRole/Get/<id>', methods=['GET'])
def get_role(id):
    role = Userroles.query.get(id)
    return role_schema.jsonify(role)

# update role
@app.route('/UserRole/Update/<id>', methods=['PUT'])
def update_role(id):
    role = Userroles.query.get(id)
    rolename = request.json['rolename']
    isactive = request.json['isactive']
    createddate = request.json['createddate']
    modifieddate = request.json['modifieddate']
    isdeleted = request.json['isdeleted']

    role.rolename = rolename
    role.isactive = isactive
    role.createddate = createddate
    role.modifieddate = modifieddate
    role.isdeleted = isdeleted

    db.session.commit()
    return role_schema.jsonify(role)


# delete role
@app.route('/UserRole/Delete/<id>', methods=['DELETE'])
def delete_role(id):
    role = Userroles.query.get(id)
    db.session.delete(role)
    db.session.commit()
    return role_schema.jsonify(role)

# for vehicle
@app.route('/Vehicle/Register', methods=['POST'])
def add_vehicles():
    licenceplate = request.json['licenceplate']
    brand = request.json['brand']
    model = request.json['model']
    year = request.json['year']
    isguest = request.json['isguest']
    isactive = request.json['isactive']
    createddate = request.json['createddate']
    modifieddate = request.json['modifieddate']
    isdeleted = request.json['isdeleted']
    vehicletypeid = request.json['vehicletypeid']
    userid = request.json['userid']

    new_vehicle = Vehicles(licenceplate, brand, model, year, isguest, isactive, createddate, modifieddate, isdeleted,
                           vehicletypeid, userid)

    db.session.add(new_vehicle)
    db.session.commit()
    return role_schema.jsonify(new_vehicle)

# get all vehicle
@app.route('/Vehicle/GetAll', methods=['GET'])
@token_required
def get_all_users(current_user):

    vehicles = Vehicles.query.all()
    output = []
    for vehicle in vehicles:
        output.append({
            'id':vehicle.id,
            'licenceplate': vehicle.licenceplate,
            'brand':vehicle.brand,
            'model': vehicle.model,
            'year': vehicle.year,
            'isguest':vehicle.isguest,
            'isactive':vehicle.isactive,
            'isdeleted':vehicle.isdeleted,
            'createddate':vehicle.createddate,
            'modifieddate':vehicle.modifieddate,
            'vehicletypeid':vehicle.vehicletypeid,
            'userid':vehicle.userid
        })

    return jsonify({'vehicles': output})

@app.route('/Values/GetToken', methods=['POST'])
def login():
    # creates dictionary of form data
    auth = request.json

    if not auth or not auth.get('email') or not auth.get('password') or not auth.get('userroleid'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )

    user = Users.query \
        .filter_by(email=auth.get('email')) \
        .first()

    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
        )

    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'id': user.id,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, app.config['SECRET_KEY'])

        return make_response(jsonify({'data': {"value": token.decode('UTF-8')}}), 200)

    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
    )

# get single vehicle
@app.route('/Vehicle/Get/<id>', methods=['GET'])
def get_vehicle(id):
    vehicle = Vehicles.query.get(id)
    return vehicle_schema.jsonify(vehicle)

# update vehicle
@app.route('/Vehicle/Update/<id>', methods=['PUT'])
def update_vehicle(id):
    vehicle = Vehicles.query.get(id)
    licenceplate = request.json['licenceplate']
    brand = request.json['brand']
    model = request.json['model']
    year = request.json['year']
    isguest = request.json['isguest']
    isactive = request.json['isactive']
    createddate = request.json['createddate']
    modifieddate = request.json['modifieddate']
    isdeleted = request.json['isdeleted']
    vehicletypeid = request.json['vehicletypeid']
    userid = request.json['userid']

    vehicle.licenceplate = licenceplate
    vehicle.brand = brand
    vehicle.model = model
    vehicle.year = year
    vehicle.isguest = isguest
    vehicle.isactive = isactive
    vehicle.createddate = createddate
    vehicle.modifieddate = modifieddate
    vehicle.isdeleted = isdeleted
    vehicle.vehicletypeid = vehicletypeid
    vehicle.userid = userid

    db.session.commit()
    return vehicle_schema.jsonify(vehicle)

# delete vehicle
@app.route('/Vehicle/Delete/<id>', methods=['DELETE'])
def delete_vehicle(id):
    vehicle = Vehicles.query.get(id)
    db.session.delete(vehicle)
    db.session.commit()
    return vehicle_schema.jsonify(vehicle)

# for vehicletypes
@app.route('/Vehicletypes/Register', methods=['POST'])
def add_vehicletypes():
    typename = request.json['typename']
    isactive = request.json['isactive']
    createddate = request.json['createddate']
    modifieddate = request.json['modifieddate']
    isdeleted = request.json['isdeleted']

    new_vehicletype = Vehicletypes(typename, isactive, createddate, modifieddate, isdeleted)

    db.session.add(new_vehicletype)
    db.session.commit()
    return vehicletype_schema.jsonify(new_vehicletype)


# get all vehicletypes
@app.route('/Vehicletypes/GetAll', methods=['GET'])
def get_vehicletypes():
    all_vehicletypes = Vehicletypes.query.all()
    result = vehicletypes_schema.dump(all_vehicletypes)
    return jsonify(result)

# get single vehicletypes
@app.route('/Vehicletypes/Get/<id>', methods=['GET'])
def get_vehicletype(id):
    vehicletype = Vehicletypes.query.get(id)
    return vehicletype_schema.jsonify(vehicletype)

# update vehicletypes
@app.route('/Vehicletypes/Update/<id>', methods=['PUT'])
def update_vehicletype(id):
    vehic = Vehicletypes.query.get(id)
    typename = request.json['vehicletype']
    isactive = request.json['isactive']
    createddate = request.json['createddate']
    modifieddate = request.json['modifieddate']
    isdeleted = request.json['isdeleted']

    vehic.typename = typename
    vehic.isactive = isactive
    vehic.createddate = createddate
    vehic.modifieddate = modifieddate
    vehic.isdeleted = isdeleted

    db.session.commit()
    return vehicletype_schema.jsonify(vehic)


# delete vehicletype
@app.route('/Vehicletypes/Delete/<id>', methods=['DELETE'])
def delete_vehicletype(id):
    vehicletype = Vehicletypes.query.get(id)
    db.session.delete(vehicletype)
    db.session.commit()
    return vehicletype_schema.jsonify(vehicletype)

# for vehiclelogins
@app.route('/Vehiclelogins/Register', methods=['POST'])
def add_vehiclelogins():
    processdate = request.json['processdate']
    isactive = request.json['isactive']
    createddate = request.json['createddate']
    modifieddate = request.json['modifieddate']
    isdeleted = request.json['isdeleted']
    vehicleid = request.json['vehicleid']
    logintypeid = request.json['logintypeid']

    new_login = Vehiclelogins(processdate, isactive, createddate, modifieddate, isdeleted, vehicleid, logintypeid)

    db.session.add(new_login)
    db.session.commit()
    return login_schema.jsonify(new_login)

@app.route('/Vehiclelogins/GetAll', methods=['GET'])
def get_logins():
    all_logins = Vehiclelogins.query.all()
    result = logins_schema.dump(all_logins)
    return jsonify(result)

# get single vehiclelogins
@app.route('/Vehiclelogins/Get/<id>', methods=['GET'])
def get_login(id):
    vehiclelogin = Vehiclelogins.query.get(id)
    return login_schema.jsonify(vehiclelogin)

# update vehiclelogins
@app.route('/Vehiclelogins/Update/<id>', methods=['PUT'])
def update_login(id):
    vehiclelogin = Vehiclelogins.query.get(id)
    processdate = request.json['processdate']
    isactive = request.json['isactive']
    createddate = request.json['createddate']
    modifieddate = request.json['modifieddate']
    isdeleted = request.json['isdeleted']
    vehicleid = request.json['vehicleid']
    logintypeid = request.json['logintypeid']

    vehiclelogin.processdate = processdate
    vehiclelogin.isactive = isactive
    vehiclelogin.createddate = createddate
    vehiclelogin.modifieddate = modifieddate
    vehiclelogin.isdeleted = isdeleted
    vehiclelogin.vehicleid = vehicleid
    vehiclelogin.logintypeid = logintypeid

    db.session.commit()
    return login_schema.jsonify(vehiclelogin)

# delete vehiclelogins
@app.route('/Vehiclelogins/Delete/<id>', methods=['DELETE'])
def delete_login(id):
    vehiclelogin = Vehiclelogins.query.get(id)
    db.session.delete(vehiclelogin)
    db.session.commit()
    return login_schema.jsonify(vehiclelogin)

# for logintypes
@app.route('/Logintypes/Register', methods=['POST'])
def add_logintype():
    typename = request.json['typename']
    isactive = request.json['isactive']
    createddate = request.json['createddate']
    modifieddate = request.json['modifieddate']
    isdeleted = request.json['isdeleted']

    new_logintype = Logintypes(typename, isactive, createddate, modifieddate, isdeleted)

    db.session.add(new_logintype)
    db.session.commit()
    return logintype_schema.jsonify(new_logintype)

# get all logintype
@app.route('/Logintypes/GetAll', methods=['GET'])
def logintypes():
    all_logintypes = Logintypes.query.all()
    result = logintypes_schema.dump(all_logintypes)
    return jsonify(result)

@app.route('/Logintypes/Update/<id>', methods=['PUT'])
def update_logintype(id):
    log = Logintypes.query.get(id)
    typename = request.json['style']
    isactive = request.json['isactive']
    createddate = request.json['createddate']
    modifieddate = request.json['modifieddate']
    isdeleted = request.json['isdeleted']

    log.typename = typename
    log.isactive = isactive
    log.createddate = createddate
    log.modifieddate = modifieddate
    log.isdeleted = isdeleted

    db.session.commit()
    return logintype_schema.jsonify(log)

# delete logintype
@app.route('/Logintypes/Delete/<id>', methods=['DELETE'])
def delete_logintype(id):
    logintype = Logintypes.query.get(id)
    db.session.delete(logintype)
    db.session.commit()
    return logintype_schema.jsonify(logintype)

if __name__ == '__main__':
    app.run(debug=True)
