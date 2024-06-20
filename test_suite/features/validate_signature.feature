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
        And The subindicationLabel is "<SubIndication>"

        Examples:
            | file                                         | Indication    | SubIndication                |
            | Signed_ok.xml                                | TOTAL_PASSED  | None                         |
            | Sign-5.xml                                   | TOTAL_FAILED  | HASH_FAILURE                 |
            | Signed_nok.xml                               | TOTAL_FAILED  | SIG_CRYPTO_FAILURE           |
            | Sign-1.bad_digest_in_timestamp.xml           | TOTAL_FAILED  | HASH_FAILURE                 |
            | Sign-1.bad_sig_in_CRL_for_BelgiumRootCA3.xml | TOTAL_FAILED  | HASH_FAILURE                 |
            | Sign-1.bad_sig_in_CRL_for_BelgiumRootCA4.xml | TOTAL_FAILED  | HASH_FAILURE                 |
            | Sign-1.bad_sig_of_EndUserCert.xml            | TOTAL_FAILED  | CRYPTO_CONSTRAINTS_FAILURE   |
            | Sign-1.bad_sig_of_IssuingCA.xml              | TOTAL_FAILED  | HASH_FAILURE                 |
