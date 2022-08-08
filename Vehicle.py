from flask import request, jsonify, make_response
from entities import Vehicles, vehicle_schema
from DatabaseConnect import app, db
import jwt

class vehicleclass:
    @app.route('/Vehicle/Register', methods=['POST'])
    def add_vehicles():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
            a = int(data["userroleid"])
            if a <= 2:
                # creates a dictionary of the form data
                data = request.json
                # gets name, email and password
                licenceplate, brand, model, year, isguest, isactive, isdeleted, vehicletypeid, userid, createddate, modifieddate = data.get(
                    'licenceplate'), data.get('brand'), data.get('model'), data.get('year'), data.get(
                    'isguest'), data.get('isactive'), data.get('isdeleted'), data.get('vehicletypeid'), data.get(
                    'userid'), data.get('createddate'), data.get(
                    'modifieddate')

                vehicle = Vehicles(
                    licenceplate=licenceplate,
                    brand=brand,
                    model=model,
                    isguest=isguest,
                    isactive=isactive,
                    isdeleted=isdeleted,
                    vehicletypeid=vehicletypeid,
                    userid=userid,
                    createddate=createddate,
                    modifieddate=modifieddate,
                    year=year
                )
                db.session.add(vehicle)
                db.session.commit()

                return make_response('Successfully registered.', 200)

        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401


    @app.route('/Vehicles/GetAll', methods=['GET'])
    def get_all_vehicles():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
            if data["userroleid"] == "1":
                vehicles = Vehicles.query.all()
                output = []
                for vehicle in vehicles:
                    if not vehicle.isdeleted:
                        output.append({
                            'id': vehicle.id,
                            'licenceplate': vehicle.licenceplate,
                            'brand': vehicle.brand,
                            'model': vehicle.model,
                            'year': vehicle.year,
                            'isguest': vehicle.isguest,
                            'isactive': vehicle.isactive,
                            'isdeleted': vehicle.isdeleted,
                            'createddate': vehicle.createddate,
                            'modifieddate': vehicle.modifieddate,
                            'vehicletypeid': vehicle.vehicletypeid,
                            'userid': vehicle.userid
                        })

                return jsonify({'vehicles': output})
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    @app.route('/Vehicle/Get', methods=['GET'])
    def get_vehicle():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')

        if 'id' in request.headers:
            id = request.headers['id']
            a = int(data["userroleid"])
            vehicles = Vehicles.query.get(id)
            print(vehicles)
            if (int(data["userid"]) == vehicles.userid) or (1 <= a <= 2):

                if vehicles != None:
                    if not vehicles.isdeleted:
                        return vehicle_schema.jsonify(vehicles)
                    else:
                        return jsonify({
                            'message': 'User not found !!'
                        }), 200
                else:
                    return jsonify({
                        'message': 'There is no such vehicle !!'
                    }), 200
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    # get single vehicle


    @app.route('/Vehicle/GetPlate', methods=['GET'])
    def get_vehicleplate():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')

        if 'licenceplate' in request.headers:
            licenceplate = request.headers['licenceplate']
            a = int(data["userroleid"])
            vehicles = Vehicles.query.filter(Vehicles.licenceplate == licenceplate).first()
            print("b", vehicles)
            if vehicles == None:
                return jsonify({
                    'message': 'Vehicle not found !!'
                }), 400

            if (int(data["userid"]) == vehicles.userid) or (1 <= a <= 2):

                if vehicles != None:
                    if not vehicles.isdeleted:
                        return vehicle_schema.jsonify(vehicles)

                    else:
                        return jsonify({
                            'message': 'User not found !!'
                        }), 200

            else:
                return jsonify({
                    'message': 'There is no such vehicle !!'
                }), 200

        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401


    @app.route('/Vehicle/Update', methods=['POST'])
    def update_vehicle():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')

        if 'id' in request.headers:
            id = request.headers['id']
            a = int(data["userroleid"])
            if (1 <= a <= 2):
                vehicle = Vehicles.query.get(id)
                if vehicle != None:
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
                    return make_response('Successfully Updated.', 200)
                else:
                    return jsonify({
                        'message': 'There is no such vehicle !!'
                    }), 200
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    # delete vehicle
    @app.route('/Vehicle/Delete', methods=['POST'])
    def delete_vehicle():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
            a = int(data["userroleid"])
            if a <= 2:
                if 'id' in request.headers:
                    id = request.headers['id']
                    vehicle = Vehicles.query.get(id)
                    if vehicle != None:
                        vehicle.isdeleted = True
                        db.session.commit()
                        return make_response('Successfully Deleted.', 200)
                    else:
                        return jsonify({
                            'message': 'There is no such vehicle !!'
                        }), 200
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

if __name__ == '__main__':
    app.run(debug=True)
