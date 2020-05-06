Feature: Signing a document

    Background: disabled SSL Verfication
        Given The ssl verification is disabled

    @active @wip
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
            | signatureValue                        | apples         | 400  | Unexpected end of base64-encoded  |
            | signatureValue                        | YXBwbGVz       | 400  | INDETERMINATE                     |
            | toSignDocument/bytes                  | apples         | 400  | Unexpected end of base64-encoded  |
            | toSignDocument/bytes                  | YXBwbGVz       | 500  | XML expected                      |
            | signingProfileId                      | YXBwbGVz       | 400  | not found                         |
            | signingProfileId                      | XADES_1        | 400  | NO_CERTIFICATE_CHAIN_FOUND        |
            | signingProfileId                      | XADES_2        | 400  | NO_CERTIFICATE_CHAIN_FOUND        |


    @active
    Scenario Outline: Sign a document
        Given Prepare the <document>
        When Send the document
        Then The response is <code>
        And The result is <result>

        Examples:
            | document      | code | result        |
            | signable.json | 400  | INDETERMINATE |


    @active @wip
    # max seems to be 1374 documents
    Scenario Outline: Sign a document
        Given Prepare the <document>
        When Send the documents
        Then The response is <code>
        And The result is <result>

        Examples:
            | document       | code | result                  |
            | signables.json | 500  | Not supported operation |
# | signable_huge.json | 400  | INDETERMINATE |