from secure_notes_server import app, mongo
from .auth import generate_token, validate_token, validate_password, compute_password_hash
from .auth import basic_auth, token_auth

from flask import request, abort, jsonify, g

import html
import string

valid_username_chars=string.digits+string.ascii_letters+string.punctuation+" "
valid_password_chars=string.digits+string.ascii_letters+string.punctuation+" "

@app.route("/login", methods=["POST"])
@basic_auth.login_required
def login_token():
    #username=request.authorization["username"]
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

@app.route("/tokentest")
@token_auth.login_required
def test_token():
    #auth_text=request.headers["Authorization"]
    #auth_list=auth_text.split()
    #if auth_list[0]!="Bearer":
    #    abort(400) # Bad request
    # Entry already guaranteed to exist by previous token verification stuff
    return g.username

@app.route("/listusers")
def list_users():
    retlist=list()
    for item in mongo.db.users.find(dict()):
        retlist.append(item)
    return html.escape(str(retlist))

@app.route("/createuser", methods=["POST"])
def create_user():
    # TODO: add messages for the bad request errors
    print("Start")
    if any((c not in valid_username_chars for c in request.authorization["username"])):
        abort(400)
    print("Username contents valid")
    if any((c not in valid_password_chars for c in request.authorization["password"])):
        abort(400)
    print("Password contents valid")
    if mongo.db.users.count_documents({"username":request.authorization["username"]})!=0:
        cursor=mongo.db.users.find({"username":request.authorization["username"]})
        print(cursor)
        for element in cursor:
            print(element)
        abort(403)
    print("Username does not exist")
    insert_document={"username":request.authorization["username"],
                     "password":compute_password_hash(request.authorization["password"]),
                     "notelist":list()}
    mongo.db.users.insert_one(insert_document)
    return '',204

@app.route("/deleteuser", methods=["POST"])
def remove_user():
    #if request.headers[]
    pass
