#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from dropbear.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            r"""Jan  8 16:39:33 tp.lan dropbear[14824]: Bad password attempt for 'root' from 193.219.28.149:48629""",
            'dropbear',
            '51003',
            5,
            id='dropbear_bad_password_attempt',
        ),
        pytest.param(
            r"""Jan  8 19:54:12 tp.lan dropbear[15197]: Login attempt for nonexistent user from 182.72.89.122:4328""",
            'dropbear',
            '51093',
            5,
            id='dropbear_bad_password_attempt_for_non_existing_user',
        ),
        pytest.param(
            r"""Jan  8 19:32:41 tp.lan dropbear[15165]: Pubkey auth succeeded for 'root' with key md5 78:d6:41:ca:78:37:80:88:1d:15:0a:68:91:d1:4e:ad from 10.10.10.241:51737""",
            'dropbear',
            '51010',
            0,
            id='dropbear_user_successfully_logged_in_using_a_public_key',
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


