import base64
import json

def read_if_exists(parserobj, section, item, default_value=None):
    if section in parserobj and item in parserobj[section]:
        return parserobj[section][item]
    else:
        return default_value

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
