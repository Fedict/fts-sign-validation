import requests
import common as c
import json


def ready_certificate_json(certificate, certificateChain):

    with open("./data/requests/certificate.json") as template:
        json_file = json.load(template)

    json_file["certificate"]["encodedCertificate"] = certificate
    json_file["certificateChain"] = certificateChain

    return json_file


def prepare_certificateChain(certificateChain):
    chainlinks = certificateChain.split()
    encoded_chainlinks = []
    certificateChain_json = []
    i = 0
    while i < len(chainlinks):
        encoded_chainlinks.append(c.encode_file(chainlinks[i]))

        with open("./data/requests/encodedCertificateChain.json") as template:
            json_file = json.load(template)

        json_file["encodedCertificate"] = encoded_chainlinks[i]
        certificateChain_json.append(json_file)

        i += 1

    return certificateChain_json


def ready_certificates_json(
    certificate, certificateChain, second_certificate, second_certificateChain
):

    with open("./data/requests/certificates.json") as template:
        json_file = json.load(template)

    json_file[0]["certificate"]["encodedCertificate"] = certificate
    json_file[0]["certificateChain"] = certificateChain
    json_file[1]["certificate"]["encodedCertificate"] = second_certificate
    json_file[1]["certificateChain"] = second_certificateChain

    return json_file


def validate_certificates(
    certificate, certificateChain, second_certificate, second_certificateChain
):
    url = c.get_url()
    json = ready_certificates_json(
        certificate, certificateChain, second_certificate, second_certificateChain
    )
    req = requests.post(
        url=url + "validation/validateCertificates", json=json, verify=False
    )

    return req


def validate_certificate(certificate, certificateChain):
    url = c.get_url()
    json = ready_certificate_json(certificate, certificateChain)

    req = requests.post(
        url=url + "validation/validateCertificate", json=json, verify=False
    )

    return req
