from flask import request, jsonify ,make_response
from entities import Logintypes, logintype_schema
from DatabaseConnect import app, db
import jwt

# for logintypes
class logintypeclass:
    @app.route('/Logintypes/Register', methods=['POST'])
    def add_logintype():
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

                new_logintype = Logintypes(typename, isactive, isdeleted,modifieddate, createddate)

                db.session.add(new_logintype)
                db.session.commit()
                return make_response('Successfully registered.', 200)
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    # get all logintype
    @app.route('/Logintypes/GetAll', methods=['GET'])
    def logintypes():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
            a = int(data["userroleid"])
            if a <= 2:
                logintypes = Logintypes.query.all()
                output = []
                for logintype in logintypes:
                    if not logintype.isdeleted:
                        output.append({
                            'id': logintype.id,
                            'typename': logintype.typename,
                            'isactive': logintype.isactive,
                            'isdeleted': logintype.isdeleted,
                            'createddate': logintype.createddate,
                            'modifieddate': logintype.modifieddate,
                        })

                return jsonify({'logintypes': output})
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    @app.route('/Logintypes/Get', methods=['GET'])
    def get_logintypes():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')

        if 'id' in request.headers:
            id = request.headers['id']
            a = int(data["userroleid"])
            if 1 <= a <= 2:
                logintypes = Logintypes.query.get(id)
                if logintypes != None:
                    if not logintypes.isdeleted:
                        return logintype_schema.jsonify(logintypes)
                    else:
                        return jsonify({
                            'message': 'User not found !!'
                        }), 200
                else:
                    return jsonify({
                        'message': 'There is no such login type !!'
                 }), 200
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    @app.route('/Logintypes/Update', methods=['POST'])
    def update_logintype():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')

        if 'id' in request.headers:
            id = request.headers['id']
            a = int(data["userroleid"])
            if 1 <= a <= 2:
                log = Logintypes.query.get(id)
                if log != None:
                    typename = request.json['typename']
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
                    return make_response('Successfully Updated.', 200)
                else:
                    return jsonify({
                        'message': 'There is no such login type !!'
                    }), 200
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    # delete logintype
    @app.route('/Logintypes/Delete', methods=['POST'])
    def delete_logintype():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
            a = int(data["userroleid"])
            if a <= 2:
                if 'id' in request.headers:
                    id = request.headers['id']
                    logintype = Logintypes.query.get(id)
                    if logintype != None:
                        logintype.isdeleted = True
                        db.session.commit()
                        return make_response('Successfully Deleted.', 200)
                    else:
                        return jsonify({
                            'message': 'There is no such login type !!'
                        }), 200
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

if __name__ == '__main__':
    app.run(debug=True)
