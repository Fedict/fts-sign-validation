from behave import given, when, then
import validate_certificate as vc
import common as c
import json


@given('Preparing the certificate "{certificate}"')
def add_certificate(context, certificate):
    context.cert_post_certificate = c.encode_file(certificate)


@given('Preparing the chain "{certificateChain}"')
def add_certificateChain(context, certificateChain):
    context.certificateChain = vc.prepare_certificateChain(certificateChain)


@given('Preparing another certificate "{certificate}"')
def add_second_certificate(context, certificate):
    context.cert_post_certificate_second = c.encode_file(certificate)


@given('Preparing another chain "{certificateChain}"')
def add_second_certificateChain(context, certificateChain):
    context.cert_post_certificateChain_second = c.encode_file(certificateChain)


@when("The user validates the certificate")
def validate_certicate(context):
    context.response = vc.validate_certificate(
        context.cert_post_certificate, context.certificateChain
    )


@then("The certificate is {result}")
def validation_result(context, result):
    response_dict = json.loads(context.response.content)
    assert (
        response_dict["simpleCertificateReport"]["ChainItem"][0]["Indication"] == result
    )


@when("The user validates the certificates")
def validate_certicates(context):
    context.response = vc.validate_certificates(
        context.cert_post_certificate,
        context.cert_post_certificateChain,
        context.cert_post_certificate_second,
        context.cert_post_certificateChain_second,
    )


@then("The results are {first_result} and {second_result}")
def validation_results(context, first_result, second_result):
    response_dict = json.loads(context.response.content)
    assert response_dict["indications"][0]["indication"] == first_result
    assert response_dict["indications"][1]["indication"] == second_result
