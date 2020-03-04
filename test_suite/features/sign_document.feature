Feature: Signing a document

    @wip
    Scenario Outline: Sign a document
        Given Add a <document> to the post
        When Send the document
        Then The response is <code>

        Examples:
            | document         | code |
            | signable.json    | 200  |
#            | old_signing.json | 400  |
#            | no_doc.json   | 400  |
#            | no_signature.json          | 400  |
#            | different_sig_algo.json    | 400  |
#            | invalid_signature.json     | 400  |
#            | invalid_b64_signature.json | 400  |
