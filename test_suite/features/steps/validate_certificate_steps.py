from behave import given, when
import validate_certificate as vc
import common as c


@given('Preparing the certificate "{certificate}"')
def add_certificate(context, certificate):
    context.cert_post_certificate = c.encode_file(certificate)


@given('Preparing the chain "{certificateChain}"')
def add_certificateChain(context, certificateChain):
    context.cert_post_certificateChain = c.encode_file(certificateChain)


@when("The user validates the certificate")
def validate_certicate(context):
    context.response = vc.validate_certificate(
        context.cert_post_certificate, context.cert_post_certificateChain
    )
