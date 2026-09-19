#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log

pytestmark = pytest.mark.wazuh_logtest


# Converted from vsftpd.ini
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            'Wed Jul 27 18:32:27 2016 [pid 2] CONNECT: Client "fe80::baac:6fff:fe7d:d2e0"',
            'vsftpd',
            '11401',
            3,
            id='connect_1',
        ),
        pytest.param(
            'Wed Jul 27 18:32:27 2016 [pid 2] CONNECT: Client "10.11.12.13"',
            'vsftpd',
            '11401',
            3,
            id='connect_2',
        ),
        pytest.param(
            'Mon Oct 24 11:32:53 2016 [pid 1] [$ALOC$] FAIL LOGIN: Client "10.55.112.101"',
            'vsftpd',
            '11403',
            5,
            id='login_1',
        ),
        pytest.param(
            'Mon Oct 24 11:32:53 2016 [pid 1] [$ALOC$] FAIL LOGIN: Client "fe80::baac:6fff:fe7d:d2e0"',
            'vsftpd',
            '11403',
            5,
            id='login_2',
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


