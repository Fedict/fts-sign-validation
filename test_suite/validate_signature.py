import requests
import common as c


def validate_signature(file):
    url = c.get_url()
    req = requests.post(
        url=url + "validation/validateSignature", json=file, verify=False
    )
    return req
