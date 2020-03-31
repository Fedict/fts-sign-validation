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


    @active @wip
    Scenario Outline: Posting different certificate
        Given Preparing the certificate "<certificate>"
        And Preparing the chain "<certificateChain>"
        When The user validates the certificate
        Then The response is <code>

        Examples:
            | certificate     | certificateChain     | code |
            | single_cert.crt | belgium.crt root.crt | 200  |


    @active
    Scenario Outline: Posting different certificate
        Given Preparing the certificate "<certificate>"
        And Preparing the chain "<certificateChain>"
        When The user validates the certificate
        Then The response is <code>
        And The certificate is <result>

        Examples:
            | certificate                     | certificateChain     | code | result        |
            | certificateChain.cer            | certificate.cer      | 200  | PASSED        |
            | Zetes+PASS+CA.crt               | certificateChain.cer | 200  | INDETERMINATE |
            | ChambersofCommerceRoot-2008.crt | certificateChain.cer | 200  | INDETERMINATE |
            | single_cert.crt                 | belgium.crt          | 500  | passed        |


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


    @active
    Scenario Outline: Posting different certificate
        Given Preparing the certificate "<certificate>"
        And Preparing the chain "<certificateChain>"
        Given Preparing another certificate "<second_certificate>"
        And Preparing another chain "<second_certificateChain>"
        When The user validates the certificates
        Then The response is <code>
        And The results are <first_result> and <second_result>

        Examples:
            | certificate          | certificateChain     | first_result  | second_certificate   | second_certificateChain | second_result | code |
            | certificate.cer      | certificateChain.cer | INDETERMINATE | certificate.cer      | certificateChain.cer    | INDETERMINATE | 200  |
            | certificateChain.cer | certificate.cer      | PASSED        | certificateChain.cer | certificate.cer         | PASSED        | 200  |

