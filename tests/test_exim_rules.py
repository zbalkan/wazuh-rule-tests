#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from exim.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""2017-01-23 03:44:14 dovecot_login authenticator failed for (hydra) [10.101.1.18]:35686: 535 Incorrect authentication data (set_id=user)""",
            'windows-date-format',
            '87502',
            5,
            id='exim_auth_failure_1',
        ),
        pytest.param(
            r"""2017-01-24 05:22:29 dovecot_plain authenticator failed for (test) [::1]:39454: 535 Incorrect authentication data (set_id=test)""",
            'windows-date-format',
            '87502',
            5,
            id='exim_auth_failure_2',
        ),
        pytest.param(
            r"""2017-01-24 03:09:46 SMTP connection from [10.101.1.10]:55010 (TCP/IP connection count = 1)""",
            'windows-date-format',
            '87504',
            0,
            id='exim_connection',
        ),
        pytest.param(
            r"""2017-01-24 02:53:13 SMTP connection from (hydra) [10.101.1.10]:53682 lost""",
            'windows-date-format',
            '87505',
            1,
            id='exim_connection_lost',
        ),
        pytest.param(
            r"""2017-01-24 05:36:23 SMTP call from (000000) [::1]:39480 dropped: too many syntax or protocol errors (last command was "123")""",
            'windows-date-format',
            '87506',
            5,
            id='exim_syntax_protocol_error',
        ),
        pytest.param(
            r'''2019-10-20 11:14:38 SMTP protocol synchronization error (input sent without waiting for greeting): rejected connection from H=[134.234.45.34] input="GET / HTTP/1.1\r\nHost: 24.255.212.213:98\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:47.0) Gecko/20100101 Firefox/47.0\r\nAccept: */*\r\n"''',
            'windows-date-format',
            '87507',
            6,
            id='exim_protocol_synchronization_error',
        ),
        pytest.param(
            r"""2019-10-20 09:56:39 H=123-123-12-123.example.example.net [123.123.12.123] F=<example@example.com> rejected RCPT <example@exampley.com>: Unrouteable address""",
            'windows-date-format',
            '87508',
            6,
            id='exim_unrouteable_address',
        ),
    ],
)
def test_rule_match(
    log: str,
    decoder: str,
    rule_id: str,
    rule_level: int,
) -> None:
    response = send_log(log)

    assert response.status is LogtestStatus.RuleMatch
    assert response.decoder == decoder
    assert response.rule_id == rule_id
    assert response.rule_level == rule_level


