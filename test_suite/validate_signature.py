import requests
import common as c
import json
from jsonschema import validate


def validate_signature(file):
    url = c.get_url()

    req = requests.post(url=url + "validation/validateSignature", json=file)

    return req


def validate_certificate_json(response):
    with open("data/requests/response_certificate_schema.json") as response_schema:
        schema = json.load(response_schema)

        return validate(instance=response, schema=schema)
