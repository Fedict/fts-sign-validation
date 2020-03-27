import requests
import common as c
import json


def ready_certificate_json(certificate, certificateChain):

    with open("./data/requests/certificate.json") as template:
        json_file = json.load(template)

    json_file["certificate"]["encodedCertificate"] = certificate.decode("utf-8")
    json_file["certificateChain"][0]["encodedCertificate"] = certificateChain.decode(
        "utf-8"
    )

    return json_file


def ready_certificates_json(
    certificate, certificateChain, second_certificate, second_certificateChain
):

    with open("./data/requests/certificates.json") as template:
        json_file = json.load(template)

    json_file[0]["certificate"]["encodedCertificate"] = certificate.decode("utf-8")
    json_file[0]["certificateChain"][0]["encodedCertificate"] = certificateChain.decode(
        "utf-8"
    )
    json_file[1]["certificate"]["encodedCertificate"] = second_certificate.decode(
        "utf-8"
    )
    json_file[1]["certificateChain"][0][
        "encodedCertificate"
    ] = second_certificateChain.decode("utf-8")

    return json_file


def validate_certificates(
    certificate, certificateChain, second_certificate, second_certificateChain
):
    url = c.get_url()
    json = ready_certificates_json(
        certificate, certificateChain, second_certificate, second_certificateChain
    )

    req = requests.post(url=url + "validation/validateCertificates", json=json)

    return req


def validate_certificate(certificate, certificateChain):
    url = c.get_url()
    json = ready_certificate_json(certificate, certificateChain)

    req = requests.post(url=url + "validation/validateCertificate", json=json)

    return req
