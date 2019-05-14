from flask import Flask
from flask_pymongo import PyMongo

import configparser

appconfig=configparser.ConfigParser()
appconfig.read("serverconfig.cfg")

if "MongoDB" not in appconfig:
    raise ValueError("Config file must contain a [MongoDB] section")

if "url" not in appconfig["MongoDB"]:
    raise ValueError("[MongoDB] config section must have a url value")

app=Flask(__name__)
app.config["DEBUG"]=True
app.config["MONGO_URI"]=appconfig["MongoDB"]["url"]
mongo=PyMongo(app)

from secure_notes_server import routes
_ = routes
