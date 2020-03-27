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
            | certificate.cer      | Sign-5.xml           | 500  |
            | Sign-5.xml           | certificate.cer      | 500  |


    @active
    Scenario Outline: Posting different certificate
        Given Preparing the certificate "<certificate>"
        And Preparing the chain "<certificateChain>"
        Given Preparing another certificate "<second_certificate>"
        And Preparing another chain "<second_certificateChain>"
        When The user validates the certificates
        Then The response is <code>

        Examples:
            | certificate          | certificateChain     | second_certificate   | second_certificateChain | code |
            | certificateChain.cer | certificate.cer      | certificateChain.cer | certificate.cer         | 200  |
            | certificate.cer      | certificateChain.cer | certificate.cer      | certificateChain.cer    | 200  |
            | Sign-5.xml           | certificate.cer      | certificateChain.cer | certificate.cer         | 500  |
            | certificate.cer      | Sign-5.xml           | certificate.cer      | certificateChain.cer    | 500  |
            | certificate.cer      | certificateChain.cer | Sign-5.xml           | certificateChain.cer    | 500  |
            | certificate.cer      | certificateChain.cer | certificate.cer      | Sign-5.xml              | 500  |
