from flask import Flask
from flask_pymongo import PyMongo

import atexit
import configparser
import os

from . import utils

appconfig=configparser.ConfigParser()
appconfig.read("serverconfig.cfg")

if "MongoDB" not in appconfig:
    raise ValueError("Config file must contain a [MongoDB] section")

if "url" not in appconfig["MongoDB"]:
    raise ValueError("[MongoDB] config section must have a url value")

app=Flask(__name__)
app.config["DEBUG"]=True
app.config["MONGO_URI"]=appconfig["MongoDB"]["url"]

app.config["SECRET_KEY"]=utils.read_if_exists(appconfig,"Flask","secret_key",os.urandom(32))
# 1hr default
app.config["token_timeout"]=int(utils.read_if_exists(appconfig,"secure_notes","token_timeout",3600))

mongo=PyMongo(app)

@atexit.register
def remove_token_db():
    print("Dropping remaining tokens")
    mongo.db.drop_collection("tokens")

from secure_notes_server import routes
_ = routes
