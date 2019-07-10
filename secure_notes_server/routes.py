from secure_notes_server import app, mongo
from .auth import generate_token, validate_token, validate_password, compute_password_hash
from .auth import basic_auth, token_auth
from . import utils

from flask import request, abort, jsonify, g
import bson

from datetime import datetime
import hmac
import html
import string

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
        "userlist":[utils.find_id_from_user(mongo.db.users,user)],
        "modified":datetime.utcnow(),
        "text":bytes(),
        "storage_format":jsonobj["storage_format"]
    }
    insert_result=mongo.db.notes.insert_one(insert_document)
    
    etag_val=utils.compute_etag(app.config["SECRET_KEY"],
                                bson.BSON.encode(insert_document))
    jsonresp=jsonify({"id":str(insert_result.inserted_id)})
    jsonresp.last_modified=insert_document["modified"]
    jsonresp.set_etag(etag_val)
    #TODO: validator fields in header
    return jsonresp, 201

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
        abort(404)
    noteobj=mongo.db.notes.find_one(id_obj)
    if noteobj is None:
        abort(404)
    if utils.find_id_from_user(mongo.db.users,user) not in noteobj["userlist"]:
        abort(403)
    etag_val=utils.compute_etag(app.config["SECRET_KEY"],
                                bson.BSON.encode(noteobj))
    #If-Modified-Since and related has only second resolution
    note_last_modified=noteobj["modified"].replace(microsecond=0)
    if etag_val in request.if_none_match \
            and note_last_modified==request.if_modified_since:
        return '',304
    modified_time=noteobj["modified"]
    del noteobj["modified"]
    #If this recurs enough, use functools.partial for this?
    noteobj["userlist"]=list(map(
        lambda userid:utils.find_user_from_id(mongo.db.users,userid),
        noteobj["userlist"]))

    base64_required=(noteobj["storage_format"]!="plain")
    jsonresp=jsonify(utils.sanitize_for_json(noteobj, base64_required))
    jsonresp.last_modified=modified_time
    jsonresp.set_etag(etag_val)
    return jsonresp

@app.route("/<user>/notes")
@token_auth.login_required
def get_note_list(user):
    if user!=g.username:
        abort(400)
    retlist=list()
    cursor=mongo.db.notes.find(
        {"userlist":
            {"$all":[utils.find_id_from_user(mongo.db.users,user)]}
        })
    for doc in cursor:
        retlist.append(str(doc["_id"]))
    return jsonify(retlist)

#Updates
@app.route("/<user>/notes/<id_>", methods=["PATCH"])
@token_auth.login_required
def update_note(user,id_):
    if user!=g.username:
        abort(400)

    try:
        id_obj=bson.objectid.ObjectId(id_)
        if not bson.objectid.ObjectId.is_valid(id_):
            raise bson.errors.InvalidId()
    except bson.errors.InvalidId:
        abort(404)

    #Check if note exists and if user is authorized to update it
    orig_note=mongo.db.notes.find_one(id_obj)
    if orig_note is None:
        abort(404)
    if utils.find_id_from_user(mongo.db.users,user) not in orig_note["userlist"]:
        abort(403)

    jsonobj=request.json
    if jsonobj is None:
        abort(400)
    #Check ETags and such to prevent the lost update problem
    etag_val=utils.compute_etag(app.config["SECRET_KEY"],
                                bson.BSON.encode(orig_note))
    if not (request.if_match and request.if_modified_since):
        abort(428)
    #If-Modified-Since and related has only second resolution
    orig_last_modified=orig_note["modified"].replace(microsecond=0)
    if not (etag_val in request.if_match
            and orig_last_modified==request.if_unmodified_since):
        abort(412)

    set_dict=dict()
    storage_format=jsonobj.get("storage_format",orig_note["storage_format"])
    for attribute_check in ["storage_format"]:
        if attribute_check in jsonobj:
            set_dict[attribute_check]=jsonobj[attribute_check]
    for attribute_check in ["title","text"]:
        if attribute_check in jsonobj:
            json_text=jsonobj[attribute_check].encode("utf-8")
            base64_required=(storage_format!="plain")
            if base64_required:
                set_dict[attribute_check]=base64.b64decode(json_text)
            else:
                set_dict[attribute_check]=json_text
    #If this recurs enough, use functools.partial for this?
    set_dict["userlist"]=list(map(
        lambda userid:utils.find_id_from_user(mongo.db.users,userid),
        jsonobj["userlist"]))
    if None in set_dict["userlist"] or len(set_dict["userlist"])==0:
        abort(400)
    set_dict["modified"]=datetime.utcnow()
    print(set_dict)
    mongo.db.notes.update_one({"_id":id_obj},{"$set":set_dict})
    return '', 204

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
    if utils.find_id_from_user(mongo.db.users,user) not in noteobj["userlist"]:
        abort(403)
    # Document guaranteed to exist by previous find_one call
    mongo.db.notes.delete_one({"_id":id_obj})
    return '', 204
