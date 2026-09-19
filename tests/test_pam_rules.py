#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from pam.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Nov 11 22:46:29 localhost su(pam_unix)[23164]: authentication failure; logname= uid=1342 euid=0 tty= ruser=dcid rhost=  user=osaudit',
            'pam',
            '5503',
            5,
            id='user_login_failed',
        ),
        pytest.param(
            'Nov 11 22:46:29 localhost vsftpd(pam_unix)[25073]: check pass; user unknown',
            'pam',
            '5504',
            5,
            id='attempt_to_login_with_an_invalid_user',
        ),
        pytest.param(
            'Nov 11 22:46:29 localhost su(pam_unix)[14592]: session opened for user news by (uid=0)',
            'pam',
            '5501',
            3,
            id='login_session_opened',
        ),
        pytest.param(
            'Nov 11 22:46:29 localhost su(pam_unix)[14592]: session closed for user news',
            'pam',
            '5502',
            3,
            id='login_session_closed',
        ),
        pytest.param(
            'Nov 11 22:46:29 localhost sshd(pam_unix)[15794]: 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.3.1  user=root',
            'pam',
            '2502',
            10,
            id='user_missed_the_password_more_than_one_time',
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


