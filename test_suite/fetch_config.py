import json


def get_configuration():
    with open("configuration.json") as json_file:
        return json.load(json_file)
