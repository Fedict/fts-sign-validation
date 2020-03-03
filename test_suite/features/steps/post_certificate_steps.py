from behave import *
import post_certificate as pc
import common as c
import json


@given('Preparing the certificate "{certificate}"')
def add_certificate(context, certificate):
    context.certificate_post_certificate = c.encode_file(certificate)


@given('Preparing the chain "{certificateChain}"')
def add_certificate(context, certificateChain):
    context.certificate_post_certificateChain = c.encode_file(certificateChain)


@when("The user validates the certificate")
def validate_certicate(context):
    context.response = pc.validate_certificate(
        context.certificate_post_certificate, context.certificate_post_certificateChain
    )
