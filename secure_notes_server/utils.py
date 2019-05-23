def read_if_exists(parserobj, section, item, default_value=None):
    if section in parserobj and item in parserobj[section]:
        return parserobj[section][item]
    else:
        return default_value
