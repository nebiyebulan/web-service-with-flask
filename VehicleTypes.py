from flask import request, jsonify, make_response
from entities import Vehicletypes, vehicletype_schema
from DatabaseConnect import app, db
import jwt
# for vehicletypes
class vehicletypeclass:
    @app.route('/Vehicletypes/Register', methods=['POST'])
    def add_vehicletypes():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
            a = int(data["userroleid"])
            if a <= 2:
                typename = request.json['typename']
                isactive = request.json['isactive']
                isdeleted = request.json['isdeleted']
                modifieddate = request.json['modifieddate']
                createddate = request.json['createddate']

                new_vehicletype = Vehicletypes(typename, isactive, isdeleted, modifieddate, createddate)

                db.session.add(new_vehicletype)
                db.session.commit()
                return make_response('Successfully registered.', 200)

        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    # get all vehicletypes
    @app.route('/Vehicletypes/GetAll', methods=['GET'])
    def get_all_vehicletypes():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
            a = int(data["userroleid"])
            if a <= 2:
                vehicletype = Vehicletypes.query.all()
                output = []
                for type in vehicletype:
                    if not type.isdeleted:
                        output.append({
                            'id': type.id,
                            'typename': type.typename,
                            'isactive': type.isactive,
                            'isdeleted': type.isdeleted,
                            'createddate': type.createddate,
                            'modifieddate': type.modifieddate,
                        })

                return jsonify({'vehicles': output})
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    # get single vehicletypes
    @app.route('/Vehicletypes/Get', methods=['GET'])
    def get_vehicletype():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')

        if 'id' in request.headers:
            id = request.headers['id']
            a = int(data["userroleid"])
            if 1 <= a <= 2:
                vehicletype = Vehicletypes.query.get(id)
                if vehicletype != None:
                    if not vehicletype.isdeleted:
                        return vehicletype_schema.jsonify(vehicletype)
                    else:
                        return jsonify({
                            'message': 'User not found !!'
                        }), 200
                else:
                    return jsonify({
                        'message': 'There is no such vehicle type !!'
                    }), 200

        return jsonify({
            'Error': 'Forbidden Authorization'
        }), 401

    # update vehicletypes
    @app.route('/Vehicletypes/Update', methods=['POST'])
    def update_vehicletype():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')

        if 'id' in request.headers:
            id = request.headers['id']
            a = int(data["userroleid"])
            if 1 <= a <= 2:
                vehic = Vehicletypes.query.get(id)
                if vehic != None:
                    typename = request.json['typename']
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
                    return make_response('Successfully Updated.', 200)
                else:
                    return jsonify({
                        'message': 'There is no such vehicle type !!'
                    }), 200

        return jsonify({
            'Error': 'Forbidden Authorization'
        }), 401

    # delete vehicletype
    @app.route('/Vehicletypes/Delete', methods=['POST'])
    def delete_vehicletype():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
            a = int(data["userroleid"])
            if a <= 2:
                if 'id' in request.headers:
                    id = request.headers['id']
                    vehicle = Vehicletypes.query.get(id)
                    if vehicle != None:
                        vehicle.isdeleted = True
                        db.session.commit()
                        return make_response('Successfully Deleted.', 200)
                    else:
                        return jsonify({
                            'message': 'There is no such vehicle type !!'
                        }), 200

        return jsonify({
            'Error': 'Forbidden Authorization'
        }), 401

if __name__ == '__main__':
    app.run(debug=True)
