import requests
import common as c
import json

from requests_toolbelt.utils import dump


def sign_document(json_request):
    url = c.get_url()

    req = requests.post(
        url=url + "signing/signDocument", json=json_request, verify=False
    )

    data = dump.dump_all(req)
    print(data.decode("utf-8"))

    return req


def fetch_json(file):
    with open("data/documents/" + file) as json_file:
        contents = json.load(json_file)

    return contents


def adapt_json(proper, value):
    with open("data/requests/signDocument.json") as template:
        json_file = json.load(template)

    properties = proper.split("/")

    if proper.count("/") == 2:
        json_file[properties[0]][properties[1]][properties[2]] = value
    elif proper.count("/") == 1:
        json_file[properties[0]][properties[1]] = value
    else:
        json_file[proper] = value

    return json_file
