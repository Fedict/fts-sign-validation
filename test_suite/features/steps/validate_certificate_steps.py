from behave import given, when
import validate_certificate as vc
import common as c


@given('Preparing the certificate "{certificate}"')
def add_certificate(context, certificate):
    context.cert_post_certificate = c.encode_file(certificate)


@given('Preparing the chain "{certificateChain}"')
def add_certificateChain(context, certificateChain):
    context.cert_post_certificateChain = c.encode_file(certificateChain)


@given('Preparing another certificate "{certificate}"')
def add_second_certificate(context, certificate):
    context.cert_post_certificate_second = c.encode_file(certificate)


@given('Preparing another chain "{certificateChain}"')
def add_second_certificateChain(context, certificateChain):
    context.cert_post_certificateChain_second = c.encode_file(certificateChain)


@when("The user validates the certificate")
def validate_certicate(context):
    context.response = vc.validate_certificate(
        context.cert_post_certificate, context.cert_post_certificateChain
    )


@when("The user validates the certificates")
def validate_certicates(context):
    context.response = vc.validate_certificates(
        context.cert_post_certificate,
        context.cert_post_certificateChain,
        context.cert_post_certificate_second,
        context.cert_post_certificateChain_second,
    )
