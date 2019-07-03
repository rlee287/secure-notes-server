from secure_notes_server import app, mongo

from flask import request, g
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from passlib.context import CryptContext

import base64
from datetime import datetime, timedelta
import hashlib
import os

pwd_context=CryptContext(schemes=["argon2","bcrypt"],
                         deprecated="auto",
                         argon2__rounds=4,
                         argon2__memory_cost=1024*1024)

basic_auth=HTTPBasicAuth()
token_auth=HTTPTokenAuth("Bearer")
# TODO: check datetime comparison directions

def generate_token(username):
    #Should not happen because of Basic Auth check but check anyway
    if mongo.db.users.count_documents({"username":username})==0:
        raise ValueError("Invalid username provided")
    assert(mongo.db.tokens.count_documents({"username":username})<=1)

    #Generate hex token but store hash in database
    #This prevents tokens from being stolen by db compromise
    tokenstr=base64.b16encode(os.urandom(32))
    tokenhash=hashlib.sha256(tokenstr).digest()
    tokenstr=tokenstr.decode("ascii")
    expire_time=datetime.utcnow()+timedelta(seconds=app.config["token_timeout"])

    if mongo.db.tokens.count_documents({"username":username})==1:
        document=mongo.db.tokens.find_one({"username":username})
        if document["expire_time"]>datetime.utcnow():
            raise ValueError("User was already given token")
        mongo.db.tokens.update_one({"username":username},
                                   {"$set":
                                        {"expire_time":expire_time,
                                        "tokenhash":tokenhash
                                        }
                                   })
        return (tokenstr, expire_time)
    mongo.db.tokens.insert_one({"expire_time":expire_time,
                                "tokenhash":tokenhash,
                                "username":username
                               })
    return (tokenstr, expire_time)

@token_auth.verify_token
def validate_token(token):
    try:
        tokenstr=token.encode("ascii")
        int(tokenstr,16) #Check that token is hex characters
    except (UnicodeEncodeError, ValueError):
        return False
    #Hash token and compare to hash in database
    tokenhash=hashlib.sha256(tokenstr).digest()
    assert(mongo.db.tokens.count_documents({"tokenhash":tokenhash})<=1)
    if mongo.db.tokens.count_documents({"tokenhash":tokenhash})==0:
        return False
    document=mongo.db.tokens.find_one({"tokenhash":tokenhash})
    if document["expire_time"]<datetime.utcnow():
        return False
    g.username=document["username"]
    return True

@basic_auth.verify_password
def validate_password(username, password):
    if request.authorization is None:
        return False
    username_count=mongo.db.users.count_documents({"username":request.authorization["username"]})
    assert(username_count<=1)
    if username_count==0:
        # Hash anyway to avoid leaking username existence via timing side channel
        compute_password_hash(password)
        return False
    userdb_entry=mongo.db.users.find({"username":request.authorization["username"]})
    verify_result=pwd_context.verify(password, userdb_entry[0]["password"])
    if verify_result:
        g.username=username
    return verify_result

def compute_password_hash(password):
    return pwd_context.hash(password)
