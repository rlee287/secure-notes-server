from secure_notes_server import app, mongo
from flask import request, abort

import html

alphanum="1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"

@app.route("/listusers")
def list_users():
    retlist=list()
    for item in mongo.db.users.find(dict()):
        retlist.append(item)
    return html.escape(str(retlist))

@app.route("/createuser", methods=["POST"])
def create_user():
    # TODO: add messages for the errors
    if len(request.form)!=1:
        abort(400)
    if "username" not in request.form:
        abort(400)
    if any((c not in alphanum for c in request.form["username"])):
        abort(400)
    mongo.db.users.insert_one({"username":request.form["username"],"notelist":list()})
    return ('',204)
