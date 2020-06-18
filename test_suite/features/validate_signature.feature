Feature: Validation signature service

    Background: disabled SSL Verfication
        Given The ssl verification is disabled

    @active
    Scenario Outline: Check if the validation service is online
        Given A ping has been sent to the "<service>"
        Then A pong will be returned

        Examples:
            | service    |
            | validation |
            | signing    |

    @active @wip
    Scenario Outline: Posting different signatures
        Given The user validates a "<file>"
        Then The indication is "<Indication>"
        And The subindication is "<SubIndication>"

        Examples:
            | file                                         | Indication    | SubIndication                |
            | Signed_ok.xml                                | TOTAL_PASSED  | None                         |
            | Sign-5.xml                                   | TOTAL_FAILED  | NO_POE                       |
            | Signed_nok.xml                               | TOTAL_FAILED  | SIG_CRYPTO_FAILURE           |
            | Sign-1.bad_digest_in_timestamp.xml           | TOTAL_FAILED  | NO_POE                       |
            | Sign-1.bad_sig_in_CRL_for_BelgiumRootCA3.xml | TOTAL_FAILED  | NO_POE                       |
            | Sign-1.bad_sig_in_CRL_for_BelgiumRootCA4.xml | TOTAL_FAILED  | NO_POE                       |
            | Sign-1.bad_sig_of_EndUserCert.xml            | INDETERMINATE | NO_SIGNING_CERTIFICATE_FOUND |
            | Sign-1.bad_sig_of_IssuingCA.xml              | TOTAL_FAILED  | NO_CERTIFICATE_CHAIN_FOUND   |
