import requests
import common as c
from requests_toolbelt.utils import dump
import json


def ready_json(certificate, certificateChain):

    with open("./data/request_certificate_json.json") as template:
        json_file = json.load(template)

    json_file["certificate"]["encodedCertificate"] = certificate.decode("utf-8")
    json_file["certificateChain"][0]["encodedCertificate"] = certificateChain.decode(
        "utf-8"
    )

    return json_file


def validate_certificates(file):
    url = c.get_url()

    req = requests.post(url=url + "validation/validateCertificates", json=file)

    return req


def validate_certificate(certificate, certificateChain):
    url = c.get_url()
    json = ready_json(certificate, certificateChain)

    req = requests.post(url=url + "validation/validateCertificate", json=json)

    return req
