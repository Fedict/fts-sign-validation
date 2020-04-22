Feature: Validation certificate service

    Background: disabled SSL Verfication
        Given The ssl verification is disabled

    @active
    Scenario Outline: Posting simple certificate
        Given Preparing the certificate "<certificate>"
        And Preparing the chain "<certificateChain>"
        When The user validates the certificate
        Then The response is <code>

        Examples:
            | certificate     | certificateChain | code |
            | root.crt        | certificate.cer  | 200  |
            | certificate.cer | root.crt         | 200  |
            | certificate.cer | Sign-5.xml       | 500  |
            | Sign-5.xml      | certificate.cer  | 500  |


    @active
    Scenario Outline: Posting longer certificateChain
        Given Preparing the certificate "<certificate>"
        And Preparing the chain "<certificateChain>"
        When The user validates the certificate
        Then The response is <code>

        Examples:
            | certificate     | certificateChain     | code |
            | single_cert.crt | belgium.crt root.crt | 200  |


    @active @wip
    Scenario Outline: Validating certificate validation result
        Given Preparing the certificate "<certificate>"
        And Preparing the chain "<certificateChain>"
        When The user validates the certificate
        Then The response is <code>
        And The certificate is <result>

        Examples:
            | certificate                     | certificateChain     | code | result        |
            | root.crt                        | certificate.cer      | 200  | PASSED        |
            | Zetes+PASS+CA.crt               | root.crt             | 200  | INDETERMINATE |
            | ChambersofCommerceRoot-2008.crt | root.crt             | 200  | INDETERMINATE |
            | single_cert.crt                 | belgium.crt root.crt | 200  | PASSED        |


    @active
    Scenario Outline: Posting several certificates
        Given Preparing the certificate "<certificate>"
        And Preparing the chain "<certificateChain>"
        Given Preparing another certificate "<second_certificate>"
        And Preparing another chain "<second_certificateChain>"
        When The user validates the certificates
        Then The response is <code>

        Examples:
            | certificate     | certificateChain            | second_certificate | second_certificateChain     | code |
            | root.crt        | belgium.crt certificate.cer | root.crt           | belgium.crt certificate.cer | 200  |
            | certificate.cer | belgium.crt root.crt        | certificate.cer    | belgium.crt root.crt        | 200  |
            | Sign-5.xml      | certificate.cer             | root.crt           | certificate.cer             | 500  |
            | certificate.cer | Sign-5.xml                  | certificate.cer    | root.crt                    | 500  |
            | certificate.cer | root.crt                    | Sign-5.xml         | root.crt                    | 500  |
            | certificate.cer | root.crt                    | certificate.cer    | Sign-5.xml                  | 500  |


    @active
    Scenario Outline: Validating the several certificates validation
        Given Preparing the certificate "<certificate>"
        And Preparing the chain "<certificateChain>"
        Given Preparing another certificate "<second_certificate>"
        And Preparing another chain "<second_certificateChain>"
        When The user validates the certificates
        Then The response is <code>
        And The results are <first_result> and <second_result>

        Examples:
            | certificate     | certificateChain | first_result  | second_certificate | second_certificateChain | second_result | code |
            | certificate.cer | root.crt         | INDETERMINATE | certificate.cer    | root.crt                | INDETERMINATE | 200  |
            | root.crt        | certificate.cer  | PASSED        | root.crt           | certificate.cer         | PASSED        | 200  |

