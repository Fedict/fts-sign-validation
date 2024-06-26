Feature: Validation certificate service

    Background: disabled SSL Verfication
        Given The ssl verification is disabled

    @active
    Scenario Outline: Posting simple certificate
        Given Preparing the certificate "<certificate>"
        And Preparing the chain "<certificateChain>"
        When The user validates the certificate
        Then The response is <code>
        And The certificate is <Indication>
        And The subindication is "<SubIndication>"

        Examples:
            | certificate     | certificateChain | code | Indication    | SubIndication                     |
            | root.crt        | certificate.cer  | 200  | PASSED        | Skip                              |
            | certificate.cer | root.crt         | 200  | INDETERMINATE | CERTIFICATE_CHAIN_GENERAL_FAILURE |
            | BAD.crt         | certificate.cer  | 500  | Skip          | Skip                              |
            | certificate.cer | BAD.crt          | 200  | INDETERMINATE | CERTIFICATE_CHAIN_GENERAL_FAILURE |

    @active
    Scenario Outline: Posting longer certificateChain
        Given Preparing the certificate "<certificate>"
        And Preparing the chain "<certificateChain>"
        When The user validates the certificate
        Then The response is <code>

        Examples:
            | certificate     | certificateChain     | code |
            | single_cert.crt | belgium.crt root.crt | 200  |


    @active
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
            #| single_cert.crt                 | belgium.crt root.crt | 200  | PASSED        |


    @active @wip
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
            | BAD.crt         | certificate.cer             | root.crt           | certificate.cer             | 500  |
            | certificate.cer | BAD.crt                     | certificate.cer    | root.crt                    | 200  |
            | certificate.cer | root.crt                    | BAD.crt            | root.crt                    | 500  |
            | certificate.cer | root.crt                    | certificate.cer    | BAD.crt                     | 200  |


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

