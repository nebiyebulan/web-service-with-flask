from flask import request, jsonify, make_response
from entities import Userroles, role_schema
from DatabaseConnect import app, db
import jwt

class roleclass:
    @app.route('/UserRole/Register', methods=['POST'])
    def add_role():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
            a = int(data["userroleid"])
            if a <= 2:
                rolename = request.json['rolename']
                isactive = request.json['isactive']
                isdeleted = request.json['isdeleted']
                modifieddate = request.json['modifieddate']
                createddate = request.json['createddate']

                new_role = Userroles(rolename, isactive, isdeleted, modifieddate, createddate)

                db.session.add(new_role)
                db.session.commit()
                return make_response('Successfully registered.', 200)

        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    @app.route('/UserRoles/GetAll', methods=['GET'])
    def get_roles():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
            a = int(data["userroleid"])
            if a <= 2:
                all_role = Userroles.query.all()
                output = []
                for role in all_role:
                    if not role.isdeleted:
                        output.append({
                            'id': role.id,
                            'rolename': role.rolename,
                            'isactive': role.isactive,
                            'created': role.createddate,
                            'isdeleted': role.isdeleted,
                            'modifieddate': role.modifieddate,
                        })
                return jsonify(output)
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    # get single role
    @app.route('/UserRole/Get', methods=['GET'])
    def get_role():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
        if 'id' in request.headers:
            id = request.headers['id']
            a = int(data["userroleid"])
            if 1 <= a <= 2:
                role = Userroles.query.get(id)
                if role != None:
                    if not role.isdeleted:
                        return role_schema.jsonify(role)
                    else:
                        return jsonify({
                            'message': 'User not found !!'
                        }), 200
                else:
                    return jsonify({
                        'message': 'There is no such role !!'
                    }), 200
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    # update role
    @app.route('/UserRole/Update', methods=['POST'])
    def update_role():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')

        if 'id' in request.headers:
            id = request.headers['id']
            a = int(data["userroleid"])
            if 1 <= a <= 2:
                role = Userroles.query.get(id)
                if role != None:
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
                    return make_response('Successfully Updated.', 200)
                else:
                    return jsonify({
                        'message': 'There is no such role !!'
                    }), 200
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

    # delete role
    @app.route('/UserRole/Delete', methods=['POST'])
    def delete_role():
        if 'Authorization' in request.headers:
            tokengetvalue = request.headers['Authorization']
            secret_key = "secret"
            data = jwt.decode(tokengetvalue, secret_key, algorithms='HS256')
            a = int(data["userroleid"])
            if a <= 2:
                if 'id' in request.headers:
                    id = request.headers['id']
                    role = Userroles.query.get(id)
                    if role != None:
                        role.isdeleted = True
                        db.session.commit()
                        return make_response('Successfully Deleted.', 200)
                    else:
                        return jsonify({
                            'message': 'There is no such role !!'
                        }), 200
        return jsonify({
            'Error': 'Forbidden Authorization !!'
        }), 401

if __name__ == '__main__':
    app.run(debug=True)
