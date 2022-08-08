from flask import request, jsonify, make_response
from entities import Vehiclelogins, login_schema , Vehicles
from DatabaseConnect import app, db
import jwt

class vehicleloginclass:
    @app.route('/Vehiclelogins/Register', methods=['POST'])
    def add_vehiclelogins():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
            a = int(data["userroleid"])
            if a <= 2:
                isactive = request.json['isactive']
                isdeleted = request.json['isdeleted']
                vehicleid = request.json['vehicleid']
                logintypeid = request.json['logintypeid']
                processdate = request.json['processdate']
                modifieddate = request.json['modifieddate']
                createddate = request.json['createddate']

                new_login = Vehiclelogins(isactive, isdeleted, vehicleid, logintypeid, processdate,modifieddate, createddate)

                db.session.add(new_login)
                db.session.commit()
                return make_response('Successfully registered.', 200)
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    @app.route('/Vehiclelogins/GetAll', methods=['GET'])
    def get_all_logins():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
            a = int(data["userroleid"])
            if a <= 2:
                logins = Vehiclelogins.query.all()
                output = []
                for login in logins:
                    if not login.isdeleted:
                        output.append({
                            'id': login.id,
                            'isactive': login.isactive,
                            'isdeleted': login.isdeleted,
                            'createddate': login.createddate,
                            'modifieddate': login.modifieddate,
                            'processdate': login.processdate,
                            'vehicleid': login.vehicleid,
                            'logintypeid': login.logintypeid
                        })
        return jsonify({'logins': output})
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    @app.route('/Vehiclelogins/Get', methods=['GET'])
    def get_login():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')

        if 'id' in request.headers:
            id = request.headers['id']
            a = int(data["userroleid"])

            vehiclelogin = Vehiclelogins.query.get(id)
            vehicles = Vehicles.query.get(id)
            if (int(data["userid"]) == vehicles.userid) or (1 <= a <= 2):
                if vehiclelogin != None:
                    if not vehiclelogin.isdeleted:
                        return login_schema.jsonify(vehiclelogin)
                    else:
                        return jsonify({
                            'message': 'User not found !!'
                        }), 200
                else:
                    return jsonify({
                        'message': 'There is no such vehicle login !!'
                    }), 200
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    @app.route('/Vehiclelogins/Update', methods=['POST'])
    def update_login():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')

        if 'id' in request.headers:
            id = request.headers['id']
            a = int(data["userroleid"])
            if 1 <= a <= 2:
                vehiclelogin = Vehiclelogins.query.get(id)
                if vehiclelogin != None:
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
                    return make_response('Successfully Updated.', 200)
                else:
                    return jsonify({
                        'message': 'There is no such vehicle login !!'
                    }), 200
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    # delete vehiclelogins
    @app.route('/Vehiclelogins/Delete', methods=['POST'])
    def delete_login():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
            a = int(data["userroleid"])
            if a <= 2:
                if 'id' in request.headers:
                    id = request.headers['id']
                    vehiclelogin = Vehiclelogins.query.get(id)
                    if vehiclelogin != None:
                        vehiclelogin.isdeleted = True
                        db.session.commit()
                        return make_response('Successfully Deleted.', 200)
                    else:
                        return jsonify({
                            'message': 'There is no such vehicle login !!'
                        }), 200
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

if __name__ == '__main__':
    app.run(debug=True)
