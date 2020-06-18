import requests
import common as c
import json
from jsonschema import validate
from requests_toolbelt.utils import dump


def validate_signature(file):
    url = c.get_url()

    req = requests.post(
        url=url + "validation/validateSignature", json=file, verify=False
    )



    data = dump.dump_all(req)
    print(data.decode("utf-8"))

    return req
