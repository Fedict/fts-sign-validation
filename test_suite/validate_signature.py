import requests
import common as c
import json
from jsonschema import validate


def validate_signature(file):
    url = c.get_url()

    req = requests.post(
        url=url + "validation/validateSignature", json=file, verify=False
    )

    return req
