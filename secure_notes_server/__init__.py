from flask import Flask
from flask_pymongo import PyMongo

import configparser
import os

appconfig=configparser.ConfigParser()
appconfig.read("serverconfig.cfg")

if "MongoDB" not in appconfig:
    raise ValueError("Config file must contain a [MongoDB] section")

if "url" not in appconfig["MongoDB"]:
    raise ValueError("[MongoDB] config section must have a url value")

app=Flask(__name__)
app.config["DEBUG"]=True
app.config["MONGO_URI"]=appconfig["MongoDB"]["url"]
if "Flask" in appconfig and "secret_key" in appconfig["Flask"]:
    app.config["SECRET_KEY"]=appconfig["Flask"]["secret_key"]
else:
    app.config["SECRET_KEY"]=os.urandom(32)

mongo=PyMongo(app)

from secure_notes_server import routes
_ = routes
