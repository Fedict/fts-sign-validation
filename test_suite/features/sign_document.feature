Feature: Signing a document

    @active
    Scenario Outline: Modify a document
        Given Add <property> and <value> to the post
        When Send the document
        Then The response is <code>
        And The result is <result>

        Examples:
            | property                              | value          | code | result                            |
            | clientSignatureParameters/signingDate | 1583325341312  | 400  | INDETERMINATE                     |
            | clientSignatureParameters/signingDate | 0              | 500  | not in certificate validity range |
            | clientSignatureParameters/signingDate | 20000000000000 | 500  | not in certificate validity range |
            # Boundary value testing
            | clientSignatureParameters/signingDate | 1496921161000  | 400  | INDETERMINATE                     |
            | clientSignatureParameters/signingDate | 2445839844000  | 400  | INDETERMINATE                     |
            | clientSignatureParameters/signingDate | 1496921160999  | 500  | not in certificate validity range |
            | clientSignatureParameters/signingDate | 2445839844001  | 500  | not in certificate validity range |
            | signatureValue/value                  | apples         | 400  | Unexpected end of base64-encoded  |
            | signatureValue/value                  | YXBwbGVz       | 400  | INDETERMINATE                     |
            | signatureValue/algorithm              | RSA_SHA512     | 400  | INDETERMINATE                     |
            | signatureValue/algorithm              | apples         | 400  | not one of the values accepted    |
            | toSignDocument/bytes                  | apples         | 400  | Unexpected end of base64-encoded  |
            | toSignDocument/bytes                  | YXBwbGVz       | 400  | INDETERMINATE                     |

    @active
    Scenario Outline: Sign a document
        Given Prepare the <document>
        When Send the document
        Then The response is <code>
        And The result is <result>

        Examples:
            | document      | code | result        |
            | signable.json | 400  | INDETERMINATE |