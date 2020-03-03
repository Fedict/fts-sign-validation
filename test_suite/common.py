import fetch_config as fc
import json
import base64
import requests
import common as c


def ping():
    url = c.get_url()
    req = requests.get(url=url + "validation/ping")

    return req


def get_url():
    config = fc.get_configuration()
    url = config["url"]

    return url


def add_bytes_json(encoded):
    with open("./data/request_validation_json.json") as template:
        json_file = json.load(template)

    json_file["signedDocument"]["bytes"] = encoded.decode("utf-8")

    return json_file

def encode_file(file):
    with open("./data/" + file, "rb") as f:
        contents = f.read()

    encoded = base64.b64encode(contents)
    
    return encoded


def change_property(json_file, property_change, value):
    if "/" in property_change:
        json_file["signedDocument"][property_change.replace("/", "")] = value
    else:
        json_file[property_change] = value

    return json_file

