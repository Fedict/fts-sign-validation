import requests
import common as c
from requests_toolbelt.utils import dump
import json


def sign_document(json_request):
    url = c.get_url()

    json_file = json.dumps(json_request)
    f = open("request.txt", "w+")
    f.write(json_file)

    req = requests.post(url=url + "signing/signDocument", json=json_request)

    data = dump.dump_all(req)
    print(data.decode("utf-8"))

    return req


def fetch_json(file):
    with open("data/documents/" + file) as json_file:
        contents = json.load(json_file)

    return contents
