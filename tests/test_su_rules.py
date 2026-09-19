#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from su.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Apr 27 15:22:23 niban su[2921936]: failed: ttyq4 changing from ldap to root',
            'su',
            '5302',
            9,
            id='su_failed',
        ),
        pytest.param(
            'Apr 27 15:22:23 niban su[234]: BAD SU ger to fwmaster on /dev/ttyp0',
            'su',
            '5301',
            5,
            id='su_bad_pass',
        ),
        pytest.param(
            'Apr 22 17:51:51 enigma su: dcid to root on /dev/ttyp1',
            'su',
            '5305',
            4,
            id='su_work_fts',
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


@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Apr 27 15:22:23 niban su(pam_unix)[23164]: authentication failure; logname= uid=1342 euid=0 tty= ruser=dcid rhost=  user=osaudit',
            'su',
            '5503',
            5,
            id='su_pam_auth_fail_1',
        ),
        pytest.param(
            'Apr 27 15:22:23 niban su(pam_unix)[2298]: authentication failure; logname= uid=1342 euid=0 tty= ruser=dcid rhost=  user=root',
            'su',
            '5503',
            5,
            id='su_pam_auth_fail_2',
        ),
    ],
)
def test_rule_does_not_match(
    log: str,
    decoder: str,
    rule_id: str,
    rule_level: int,
) -> None:
    response = send_log(log)

    assert response.status is not LogtestStatus.Error
    assert (
        response.decoder,
        response.rule_id,
        response.rule_level,
    ) != (
        decoder,
        rule_id,
        rule_level,
    )


