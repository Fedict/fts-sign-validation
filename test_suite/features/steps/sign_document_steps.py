from behave import *
import common as c
import sign_document as sd
import json


@given("Add {property} and {value} to the post")
def prepare_post(context, property, value):
    json = sd.adapt_json(property, value)
    context.request_json = json


@when("Send the document")
def sign_document(context):
    context.response = sd.sign_document(context.request_json)
