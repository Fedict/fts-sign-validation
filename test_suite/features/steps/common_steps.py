from behave import given, then
import common as c


@given("A ping has been sent to the {service}")
def post_ping(context, service):
    context.response = c.ping(service)


@then("A pong will be returned")
def ping_response(context):
    assert context.response.status_code == 200
    assert context.response.text == "pong"


@then("The response has code '{code}'")
def validate_status_code(context, code):
    assert context.response.status_code == code


@then("The response is {code}")
def validate_response(context, code):
    assert context.response.status_code == int(code)
