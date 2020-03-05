Feature: Validation certificate service

    @active
    Scenario Outline: Posting different certificate
        Given Preparing the certificate "<certificate>"
        And Preparing the chain "<certificateChain>"
        When The user validates the certificate
        Then The response is <code>

        Examples:
            | certificate          | certificateChain     | code |
            | certificateChain.cer | certificate.cer      | 200  |
            | certificate.cer      | certificateChain.cer | 200  |
# | CZ.cer      | Sign-5.xml       | 404  |
# | Sign-5.xml  | CZ.cer           | 404  |
