from behave import *
import common as c
import sign_document as sd
import json


@given("Add a {file} to the post")
def prepare_post(context, file):
    json = sd.fetch_json(file)
    context.request_json = json


@when("Send the document")
def sign_document(context):
    context.response = sd.sign_document(context.request_json)
