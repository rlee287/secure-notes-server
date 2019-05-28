from flask import Flask
from flask_pymongo import PyMongo

import atexit
import configparser
import os

from . import utils

appconfig=configparser.ConfigParser()
appconfig.read("serverconfig.cfg")

if not utils.check_if_exists(appconfig, "MongoDB", "url"):
    raise ValueError("Config file must have [MongoDB] section with url value")
if not utils.check_if_exists(appconfig, "Flask", "secret_key"):
    raise ValueError("Config file must have [Flask] section with secret_key value")

app=Flask(__name__)
app.config["DEBUG"]=True
app.config["MONGO_URI"]=appconfig["MongoDB"]["url"]

app.config["SECRET_KEY"]=appconfig["Flask"]["secret_key"]
# 1hr default
app.config["token_timeout"]=int(utils.read_if_exists(appconfig,"secure_notes","token_timeout",3600))

mongo=PyMongo(app)

@atexit.register
def remove_token_db():
    print("Dropping remaining tokens")
    mongo.db.drop_collection("tokens")

from secure_notes_server import routes
_ = routes
