from behave import *
import post_validation as pv
import common as c
import json


@then('The indication is "{Indication}"')
def validation_Indication(context, Indication):
    assert context.response.status_code == 200
    response_dict = json.loads(context.response.content)
    i = 0
    while i < len(response_dict["SimpleReport"]["Signature"]):
        assert response_dict["SimpleReport"]["Signature"][i]["Indication"] == Indication
        i += 1


@then('The subindication is "{SubIndication}"')
def validation_subconclusion(context, SubIndication):
    response_dict = json.loads(context.response.content)
    i = 0
    while i < len(response_dict["SimpleReport"]["Signature"]):
        if response_dict["SimpleReport"]["Signature"][i]["SubIndication"] is None:
            return True
        else:
            assert (
                response_dict["SimpleReport"]["Signature"][i]["SubIndication"]
                == SubIndication
            )
            i += 1


@then("All {amount} of signatures are found")
def validation_signatures(context, amount):
    response_dict = json.loads(context.response.content)
    assert str(len(response_dict["DiagnosticData"]["Signature"])) == amount


@then("The response schema is valid")
def validate_schema(context):
    assert pv.validate_json(json.loads(context.response.content)) is None


@when('Add {naughtystring} to the "{value}"')
def replace_signatureid(context, value, naughtystring):
    json_post = c.change_property(context.json_file, value, naughtystring)
    context.response = pv.validate_signature(json_post)


@then("The response is {code}")
def validate_response(context, code):
    assert context.response.status_code == int(code)
