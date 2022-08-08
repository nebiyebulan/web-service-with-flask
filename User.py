from flask import request, make_response, jsonify
from entities import Users, user_schema, Vehicles
from werkzeug.security import generate_password_hash, check_password_hash
from DatabaseConnect import db, app
import jwt
import requests
import json

from UserRole import roleclass
from LoginTypes import logintypeclass
from Vehicle import vehicleclass
from VehicleLogins import vehicleloginclass
from VehicleTypes import vehicletypeclass

@app.route('/User/Register', methods=['POST'])
def signup():
    if 'Authorization' in request.headers:
        tokengetvalue = request.headers['Authorization']
        secret_key = "secret"
        data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
        a = int(data["userroleid"])
        if a <= 2:
            # creates a dictionary of the form data
            data = request.json

            # gets name, email and password
            username, email, phonenumber, createddate, modifieddate, isactive, isdeleted, userroleid = data.get(
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
    return jsonify({
        'Error': 'Forbidden Authorization !!'
    }), 401
# get all users
@app.route('/User/GetAll', methods=['GET'])
def get_users():
    if 'Authorization' in request.headers:
        tokengetvalue = request.headers['Authorization']
        secret_key = "secret"
        data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
        a = int(data["userroleid"])
        if a <= 2:
            all_users = Users.query.all()
            output = []
            for user in all_users:
                if not user.isdeleted:
                    output.append({
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'password': user.password,
                        'phonenumber': user.phonenumber,
                        'isactive': user.isactive,
                        'isdeleted': user.isdeleted,
                        'created': user.createddate,
                        'modifieddate': user.modifieddate,
                        'userroleid': user.userroleid
                    })

            return jsonify(output)

    return jsonify({
        "Authenticate": "Forbidden Authenticate"
    }), 401
# get single users
@app.route('/User/Get', methods=['GET'])
def get_user():
    if 'Authorization' in request.headers:
        tokengetvalue = request.headers['Authorization']
        secret_key = "secret"
        data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')

    if 'id' in request.headers:
        id = request.headers['id']
        a = int(data["userroleid"])
        if(data["userid"]==id) or (1 <= a <= 2):
            user = Users.query.get(id)
            if user != None:
                if not user.isdeleted:
                    return user_schema.jsonify(user)
                else:
                    return jsonify({
                        'message': 'User not found !!'
                    }), 200
            else:
                return jsonify({
                    'message': 'There is no such user !!'
                }), 200
        else:
            return jsonify({
                'Error': 'Forbidden Authorization'
            }), 401
# update users
@app.route('/User/Update', methods=['POST'])
def update_users():
    if 'Authorization' in request.headers:
        tokengetvalue = request.headers['Authorization']
        secret_key = "secret"
        data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')

    if 'id' in request.headers:
        id = request.headers['id']
        a = int(data["userroleid"])
        if 1 <= a <= 2:
            user = Users.query.get(id)
            if user != None:
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
                return make_response('Successfully Updated.', 200)
            else:
                return jsonify({
                    'message': 'There is no such user !!'
                }), 200
        else:
            return jsonify({
                'Error': 'Forbidden Authorization'
            }), 401
# delete users
@app.route('/User/Delete', methods=['POST'])
def delete_users():
    if 'Authorization' in request.headers:
        tokengetvalue = request.headers['Authorization']
        secret_key = "secret"
        data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
        a = int(data["userroleid"])
        if a <= 2:
            if 'id' in request.headers:
                id = request.headers['id']
                user = Users.query.get(id)
                if user != None:
                    user.isdeleted = True
                    db.session.commit()

                    vehicles = Vehicles.query.all()
                    output = []
                    for vehicle in vehicles:

                        output.append({
                            'id':vehicle.id,
                            'isdeleted': vehicle.isdeleted,
                            'userid': vehicle.userid
                        })
                    for i in output:
                        if user.id==i['userid']:
                            a = i['id']
                            print(i['id'])
                            vehicle = Vehicles.query.get(a)
                            if vehicle != None:
                                vehicle.isdeleted = True
                                db.session.commit()
                                return make_response('Successfully Deleted.', 200)
                            else:
                                return jsonify({
                                    'message': 'There is no such vehicle !!'
                                }), 200

                    return make_response('Successfully Deleted.', 200)
                else:
                    return jsonify({
                        'message': 'There is no such user !!'
                    }), 200
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401
@app.route('/Values/GetToken', methods=['POST'])
def login():
    # creates dictionary of form data
    auth = request.json

    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )

    user = Users.query.filter(Users.email == auth.get('email')).first()
    if user == None:
        return jsonify({
            'message': 'Email not found !!'
        }), 400
    if user.isdeleted == True:
        return make_response({
            "Error": 'Email And Password is Wrong',
        }), 404

    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="User does not exist !!"'}
        )
    if check_password_hash(user.password, auth.get('password')):
        id = user.id
        email = user.email
        userroleid = user.userroleid

        payload = json.dumps({
            "id": id,
            "email": email,
            "userroleid": userroleid,

        })

        headers = {
            'Content-Type': 'application/json'
        }
        response = requests.request("POST", url="http://212.154.65.92:8087/Values/GetToken", data=payload, headers=headers)
        return jsonify({
            'token': response.text
        }), 200

if __name__ == '__main__':
    app.run(debug=True)
