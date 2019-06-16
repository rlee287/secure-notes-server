import base64
import hmac
import json

#Config parser helper functions
def check_if_exists(parserobj, section, item):
    return section in parserobj and item in parserobj[section]

def read_if_exists(parserobj, section, item, default_value=None):
    if check_if_exists(parserobj, section, item):
        return parserobj[section][item]
    else:
        return default_value

#Compute ETags for notes
def compute_etag(key, message):
    return hmac.new(key, message, "sha256").hexdigest()

#Sanitize binary data from BSON for JSON via Base64 encoding
def sanitize_for_json(dictobj, use_base64=False):
    retdict=dictobj.copy()
    # Make copy for immutability reasons
    for key in iter(dictobj.keys()):
        try:
            json.dumps(retdict[key])
        except (TypeError,OverflowError):
            if isinstance(retdict[key], bytes):
                if use_base64:
                    retdict[key]=base64.b64encode(retdict[key]).decode("utf-8")
                else:
                    retdict[key]=retdict[key].decode("utf-8")
            else:
                retdict[key]=str(retdict[key])
    return retdict

#Convert username to id and vice versa
#Explicitly pass in the db object to avoid circular imports
def find_user_from_id(userdb, id_obj):
    user_obj=userdb.find_one(id_obj)
    if user_obj is None:
        return None
    else:
        return user_obj["username"]

def find_id_from_user(userdb, username):
    user_obj=userdb.find_one({"username":username})
    if user_obj is None:
        return None
    else:
        return user_obj["_id"]
