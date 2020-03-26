import fetch_config as fc
import json
import base64
import requests
import common as c


def ping(service):
    url = c.get_url()
    if service == "validation":
        req = requests.get(url=url + "validation/ping")
    else:
        req = requests.get(url=url + "signing/ping")

    return req


def get_url():
    config = fc.get_configuration()
    url = config["url"]

    return url


def add_bytes_json(encoded):
    with open("./data/requests/validation.json") as template:
        json_file = json.load(template)

    json_file["signedDocument"]["bytes"] = encoded.decode("utf-8")

    return json_file


def encode_file(file):
    if file[-3:] in ["cer", "pem"]:
        with open("./data/certificate/" + file, "rb") as f:
            contents = f.read()
    elif file[-3:] in ["xml"]:
        with open("./data/signed_documents/" + file, "rb") as f:
            contents = f.read()
    else:
        with open("./data/documents/" + file, "rb") as f:
            contents = f.read()

    encoded = base64.b64encode(contents)

    return encoded


def change_property(json_file, property_change, value):
    if "/" in property_change:
        json_file["signedDocument"][property_change.replace("/", "")] = value
    else:
        json_file[property_change] = value

    return json_file
