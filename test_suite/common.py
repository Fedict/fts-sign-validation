import json
import base64
import requests


def get_configuration():
    with open("configuration.json") as json_file:
        return json.load(json_file)


def ping(service):
    url = get_url()
    if service == "validation":
        req = requests.get(url=url + "validation/ping", verify=False)
    else:
        req = requests.get(url=url + "signing/ping", verify=False)

    return req


def get_url():
    config = get_configuration()
    url = config["url"]

    return url


def add_bytes_json(encoded):
    with open("./data/requests/validation.json") as template:
        json_file = json.load(template)

    json_file["signedDocument"]["bytes"] = encoded.decode("utf-8")

    return json_file


def encode_file(file):
    if file[-3:] in ["pem"]:
        with open("./data/certificate/" + file, "rb") as f:
            contents = f.read()
    elif file[-3:] in ["xml"]:
        with open("./data/signed_documents/" + file, "rb") as f:
            contents = f.read()
    elif file[-3:] in ["crt", "cer"]:
        with open("./data/certificate/" + file, "rt") as f:
            encoded = f.read()
            contents = encoded.replace("\n", "")

            return contents[27:-25]

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
