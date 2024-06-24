from behave import given, then, when
import validate_signature as vs
import common as c
import json


@given('The user validates a "{file}"')
def validation_file(context, file):
    encoded = c.encode_file(file)
    json = c.add_bytes_json(encoded)
    context.response = vs.validate_signature(json)


@given("The user prepares the post")
def ready_post(context):
    encoded = c.encode_file("/Signed_ok.xml")
    context.json_file = c.add_bytes_json(encoded)


@then('The indication is "{Indication}"')
def validation_Indication(context, Indication):
    response_dict = json.loads(context.response.content)
    assert context.response.status_code == 200
    assert response_dict["indication"] == Indication


@then('The subindicationLabel is "{SubIndication}"')
def validation_subconclusion(context, SubIndication):
    response_dict = json.loads(context.response.content)
    if response_dict["subIndicationLabel"] is None:
        return True
    else:
        assert response_dict["subIndicationLabel"] == SubIndication

@when('Add {naughtystring} to the "{value}"')
def replace_signatureid(context, value, naughtystring):
    json_post = c.change_property(context.json_file, value, naughtystring)
    context.response = vs.validate_signature(json_post)
