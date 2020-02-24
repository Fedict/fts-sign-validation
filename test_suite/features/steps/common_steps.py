from behave import *
import post_validation as pv
import common as c


@given("A ping has been sent to the service")
def post_ping(context):
    context.response = pv.ping()


@then("A pong will be returned")
def ping_response(context):
    assert context.response.status_code == 200
    assert context.response.text == "pong"


@then("The response has code '{code}'")
def validate_status_code(context, code):
    assert context.response.status_code == code


@given('The user uploads "{file}"')
def validation_file(context, file):
    json = c.add_bytes_json(file)
    context.response = pv.validate_signature(json)
