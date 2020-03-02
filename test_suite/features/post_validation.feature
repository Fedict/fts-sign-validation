Feature: Validation service

    @active
    Scenario: Check if the service is online
        Given A ping has been sent to the service
        Then A pong will be returned

    @active
    Scenario Outline: Posting different signatures
        Given The user uploads "<file>"
        Then The indication is "<Indication>"
        And The subindication is "<SubIndication>"
        And All <amount> of signatures are found

        Examples:
            | file                                         | Indication    | SubIndication                | amount |
            | Signed_ok.xml                                | TOTAL_PASSED  | None                         | 1      |
            | Sign-5.xml                                   | INDETERMINATE | NO_POE                       | 1      |
            | Signed_nok.xml                               | TOTAL_FAILED  | SIG_CRYPTO_FAILURE           | 1      |
            | Sign-1.bad_digest_in_timestamp.xml           | INDETERMINATE | NO_POE                       | 1      |
            | Sign-1.bad_sig_in_CRL_for_BelgiumRootCA3.xml | INDETERMINATE | NO_POE                       | 1      |
            | Sign-1.bad_sig_in_CRL_for_BelgiumRootCA4.xml | INDETERMINATE | NO_POE                       | 1      |
            | Sign-1.bad_sig_of_EndUserCert.xml            | INDETERMINATE | NO_SIGNING_CERTIFICATE_FOUND | 1      |
            | Sign-1.bad_sig_of_IssuingCA.xml              | INDETERMINATE | NO_CERTIFICATE_CHAIN_FOUND   | 1      |

    @active
    Scenario Outline: Validate json schema
        Given The user uploads "<file>"
        Then The response schema is valid

        Examples:
            | file                                         |
            | Signed_ok.xml                                |
            | Sign-5.xml                                   |
            | Signed_nok.xml                               |
            | Sign-1.bad_digest_in_timestamp.xml           |
            | Sign-1.bad_sig_in_CRL_for_BelgiumRootCA3.xml |
            | Sign-1.bad_sig_in_CRL_for_BelgiumRootCA4.xml |
            | Sign-1.bad_sig_of_EndUserCert.xml            |
            | Sign-1.bad_sig_of_IssuingCA.xml              |
