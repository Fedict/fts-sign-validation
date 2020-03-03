Feature: NaughtyString test

    @security @active
    Scenario: Check if the service is online
        Given A ping has been sent to the service
        Then A pong will be returned

    @security @active
    Scenario Outline: Send NaughtyStrings in signature
        Given The user prepares the post
        When Add <naughtystring> to the "signatureId"
        Then The response is <code>

        Examples:
            | naughtystring                                                                                                            | code |
            | null                                                                                                                     | 200  |
            | undefined                                                                                                                | 200  |
            | NULL                                                                                                                     | 200  |
            | true                                                                                                                     | 200  |
            | false                                                                                                                    | 200  |
            | hasOwnProperty                                                                                                           | 200  |
            | 0xffffffff                                                                                                               | 200  |
            | /dev/null; touch /tmp/blns.fail ; echo                                                                                   | 200  |
            | Craig Cockburn, Software Specialist                                                                                      | 200  |
            | COM1                                                                                                                     | 200  |
            | $HOME                                                                                                                    | 200  |
            | 和製漢語                                                                                                                 | 200  |
            | 울란바토르                                                                                                               | 200  |
            | 𐐡𐐀𐐖𐐇𐐤𐐓𐐝 𐐱𐑂 𐑄 𐐔𐐇𐐝𐐀𐐡𐐇𐐓 𐐏𐐆𐐅𐐤𐐆𐐚𐐊𐐡𐐝𐐆𐐓𐐆 | 200  |
            | 表ポあA鷗ŒéＢ逍Üßªąñ丂㐀𠀀                                                                                           | 200  |

    @security @deactive
    Scenario Outline: Send NaughtyStrings in signature
        Given The user prepares the post
        When Add <naughtystring> to the "/bytes"
        Then The response is <code>

        Examples:
            | naughtystring | code |
    #| null          | 400  |
    #| dW5kZWZpbmVk  | 400  |
    #| YXBwbGVz      | 400  |

    @security @active @wip
    Scenario Outline: Send NaughtyStrings in signature
        Given The user prepares the post
        When Add <naughtystring> to the "/name"
        Then The response is <code>

        Examples:
            | naughtystring                                                                                                            | code |
            | null                                                                                                                     | 200  |
            | undefined                                                                                                                | 200  |
            | NULL                                                                                                                     | 200  |
            | true                                                                                                                     | 200  |
            | false                                                                                                                    | 200  |
            | hasOwnProperty                                                                                                           | 200  |
            | 0xffffffff                                                                                                               | 200  |
            | /dev/null; touch /tmp/blns.fail ; echo                                                                                   | 200  |
            | Craig Cockburn, Software Specialist                                                                                      | 200  |
            | COM1                                                                                                                     | 200  |
            | $HOME                                                                                                                    | 200  |
            | 和製漢語                                                                                                                 | 200  |
            | 울란바토르                                                                                                               | 200  |
            | 𐐡𐐀𐐖𐐇𐐤𐐓𐐝 𐐱𐑂 𐑄 𐐔𐐇𐐝𐐀𐐡𐐇𐐓 𐐏𐐆𐐅𐐤𐐆𐐚𐐊𐐡𐐝𐐆𐐓𐐆 | 200  |
            | 表ポあA鷗ŒéＢ逍Üßªąñ丂㐀𠀀                                                                                           | 200  |