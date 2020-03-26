from behave import given, when, then
import sign_document as sd


@given("Add {property} and {value} to the post")
def prepare_post(context, property, value):
    json = sd.adapt_json(property, value)
    context.request_json = json


@when("Send the document")
def sign_document(context):
    context.response = sd.sign_document(context.request_json)


@then("The result is {result}")
def sign_doc_result(context, result):
    assert result in context.response.text
