Feature: Signing a document

    @wip
    Scenario Outline: Sign a document
        Given Add <property> and <value> to the post
        When Send the document
        Then The response is <code>

        Examples:
            | property                            | value          | code |
            | parameters/blevelParams/signingDate | 1583325341312  | 200  |
            | parameters/blevelParams/signingDate | 0              | 500  |
            | parameters/blevelParams/signingDate | 20000000000000 | 500  |
            # Boundary value testing
            | parameters/blevelParams/signingDate | 1496921161000  | 200  |
            | parameters/blevelParams/signingDate | 2445839844000  | 200  |
            | parameters/blevelParams/signingDate | 1496921160999  | 500  |
            | parameters/blevelParams/signingDate | 2445839844001  | 500  |
            | signatureValue/value                | apples         | 400  |
            | signatureValue/value                | YXBwbGVz       | 200  |
            | signatureValue/algorithm            | RSA_SHA512     | 200  |
            | signatureValue/algorithm            | apples         | 400  |
            | toSignDocument/bytes                | apples         | 400  |
            | toSignDocument/bytes                | YXBwbGVz       | 200  |











#            | old_signing.json | 400  |
#            | no_doc.json   | 400  |
#            | no_signature.json          | 400  |
#            | different_sig_algo.json    | 400  |
#            | invalid_signature.json     | 400  |
#            | invalid_b64_signature.json | 400  |
