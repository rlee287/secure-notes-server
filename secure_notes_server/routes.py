from secure_notes_server import app, mongo
from .auth import generate_token, validate_token, validate_password, compute_password_hash
from .auth import basic_auth, token_auth
from . import utils

from flask import request, abort, jsonify, g
import bson

from datetime import datetime
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

@app.route("/<user>",methods=["POST"])
@app.route("/createuser", methods=["POST"])
def create_user(user=None):
    # TODO: add messages for the bad request errors
    if request.authorization is None:
        abort(400)
    if user is not None and user!=request.authorization["username"]:
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
    return '',201

@app.route("/deleteuser", methods=["POST"])
@app.route("/<user>", methods=["DELETE"])
@token_auth.login_required
def remove_user(user=None):
    if user is not None and user!=g.username:
        abort(400)
    assert(mongo.db.users.count_documents({"username":g.username})<=1)
    # Make sure to delete all in case there is more than one entry
    mongo.db.tokens.delete_many({"username":g.username})
    mongo.db.users.find_one_and_delete({"username":g.username})
    # TODO: handle notes
    return '',204

# Note CRUD operations

#Creation
@app.route("/<user>/notes", methods=["POST"])
@token_auth.login_required
def create_note(user):
    if user!=g.username:
        abort(400)
    jsonobj=request.json
    if jsonobj is None:
        abort(400)
    if "title" not in jsonobj and "storage_format" not in jsonobj:
        abort(400)
    # FINISH
    insert_document={
        "title":jsonobj["title"].encode("utf-8"),
        "userlist":[g.username],
        "modified":datetime.utcnow(),
        "text":bytes(),
        "storage_format":jsonobj["storage_format"]
    }
    #TODO: validator fields in header
    insert_result=mongo.db.notes.insert_one(insert_document)
    return jsonify({"id":str(insert_result.inserted_id)}), 201

#Retrieval (individual, list)
@app.route("/<user>/notes/<id_>")
@token_auth.login_required
def retrieve_note(user,id_):
    if user!=g.username:
        abort(400)
    try:
        id_obj=bson.objectid.ObjectId(id_)
        if not bson.objectid.ObjectId.is_valid(id_):
            raise bson.errors.InvalidId()
    except bson.errors.InvalidId:
        abort(400)
    noteobj=mongo.db.notes.find_one(id_obj)
    if noteobj is None:
        abort(404)
    if g.username not in noteobj["userlist"]:
        abort(403)
    base64_required=(noteobj["storage_format"]!="plain")
    return jsonify(utils.sanitize_for_json(noteobj, base64_required))

@app.route("/<user>/notes")
@token_auth.login_required
def get_note_list(user):
    if user!=g.username:
        abort(400)
    retlist=list()
    cursor=mongo.db.notes.find({"userlist":{"$all":[user]}})
    for doc in cursor:
        retlist.append(str(doc["_id"]))
    return html.escape(str(retlist))

#Updates
#TODO

#Deletion
@app.route("/<user>/notes/<id_>", methods=["DELETE"])
@token_auth.login_required
def delete_note(user, id_):
    if user!=g.username:
        abort(400)
    try:
        id_obj=bson.objectid.ObjectId(id_)
        if not bson.objectid.ObjectId.is_valid(id_):
            raise bson.errors.InvalidId()
    except bson.errors.InvalidId:
        abort(400)
    noteobj=mongo.db.notes.find_one(id_obj)
    if noteobj is None:
        abort(404)
    if g.username not in noteobj["userlist"]:
        abort(403)
    # Document guaranteed to exist by previous find_one call
    mongo.db.notes.delete_one({"_id":id_obj})
    return '', 204

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

@app.route("/listnotes")
def list_notes():
    retlist=list()
    for item in mongo.db.notes.find(dict()):
        retlist.append(item)
    return html.escape(str(retlist))
