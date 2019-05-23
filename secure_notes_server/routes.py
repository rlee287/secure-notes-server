from secure_notes_server import app, mongo
from .auth import generate_token, validate_token, validate_password, compute_password_hash
from .auth import basic_auth, token_auth

from flask import request, abort, jsonify, g

import html
import string

valid_username_chars=string.digits+string.ascii_letters+string.punctuation+" "
valid_password_chars=string.digits+string.ascii_letters+string.punctuation+" "

# Login and logout

@app.route("/login", methods=["POST"])
@basic_auth.login_required
def login_token():
    # basic auth stuff already checked password
    try:
        token, expiration=generate_token(g.username)
    except ValueError:
        abort(403) # Forbidden
    return jsonify({"token":token,"token_expiration":expiration})

@app.route("/logout", methods=["POST"])
@token_auth.login_required
def logout_token():
    mongo.db.tokens.find_one_and_delete({"username":g.username})
    assert mongo.db.tokens.count_documents({"username":g.username})==0
    return '',204

# User creation and deletion

@app.route("/createuser", methods=["POST"])
def create_user():
    # TODO: add messages for the bad request errors
    if request.authorization is None:
        abort(400)
    if any((c not in valid_username_chars for c in request.authorization["username"])):
        abort(400)
    if any((c not in valid_password_chars for c in request.authorization["password"])):
        abort(400)
    if mongo.db.users.count_documents({"username":request.authorization["username"]})!=0:
        cursor=mongo.db.users.find({"username":request.authorization["username"]})
        print(cursor)
        for element in cursor:
            print(element)
        abort(403)
    insert_document={"username":request.authorization["username"],
                     "password":compute_password_hash(request.authorization["password"]),
                     "notelist":list()}
    mongo.db.users.insert_one(insert_document)
    return '',204

@app.route("/deleteuser", methods=["POST"])
@token_auth.login_required
def remove_user():
    assert(mongo.db.users.count_documents({"username":g.username})<=1)
    # Make sure to delete all in case there is more than one entry
    mongo.db.tokens.delete_many({"username":g.username})
    mongo.db.users.find_one_and_delete({"username":g.username})
    # TODO: handle notes

# Development test endpoints
@app.route("/tokentest")
@token_auth.login_required
def test_token():
    return g.username

@app.route("/listusers")
def list_users():
    retlist=list()
    for item in mongo.db.users.find(dict()):
        retlist.append(item)
    return html.escape(str(retlist))
