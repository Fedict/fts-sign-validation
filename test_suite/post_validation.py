import requests
import fetch_config as fc
import common as c
from requests_toolbelt.utils import dump
import json
from jsonschema import validate


def ping():
    url = c.get_url()
    req = requests.get(url=url + "validation/ping")

    return req


def validate_signature(file):
    url = c.get_url()

    # kept in comment in order to troubleshoot faster
    # json_request = json.dumps(file)
    # f = open("request.txt", "w+")
    # f.write(json_request)

    req = requests.post(url=url + "validation/validateSignature", json=file)

    # data = dump.dump_all(req)
    # print(data.decode("utf-8"))

    return req


def validate_json(response):
    with open("data/response_schema.json") as response_schema:
        schema = json.load(response_schema)

        return validate(instance=response, schema=schema)
